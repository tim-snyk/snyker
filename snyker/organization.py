from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional, Dict, Any
import concurrent.futures
import logging
import json

from pydantic import BaseModel, Field, PrivateAttr

from snyker.config import API_CONFIG # For loading_strategy

if TYPE_CHECKING:
    from .api_client import APIClient
    # Use forward references for models that will be refactored
    from .group import GroupPydanticModel
    from .project import ProjectPydanticModel
    from .issue import IssuePydanticModel
    from .policy import PolicyPydanticModel

API_VERSION_ORG = "2024-10-15"

class OrganizationAttributes(BaseModel):
    """Attributes of a Snyk Organization."""
    name: str
    slug: str
    is_personal: Optional[bool] = None
    created_at: Optional[str] = None

class OrgGroupRelationshipData(BaseModel):
    """Data for the relationship between an Organization and its Group."""
    id: str
    type: str # Should be "group"

class OrgGroupRelationship(BaseModel):
    """Relationship link between an Organization and its Group."""
    data: OrgGroupRelationshipData

class OrganizationRelationships(BaseModel):
    """Relationships of a Snyk Organization."""
    group: Optional[OrgGroupRelationship] = None

class OrganizationPydanticModel(BaseModel):
    """Represents a Snyk Organization.

    Provides methods to access and manage entities within the organization,
    such as projects, issues, policies, and integrations.

    Attributes:
        id: The unique identifier of the organization.
        type: The type of the Snyk entity (should be "org").
        attributes: Detailed attributes of the organization.
        relationships: Relationships to other Snyk entities, like its parent group.
    """
    id: str
    type: str
    attributes: OrganizationAttributes
    relationships: Optional[OrganizationRelationships] = None

    _api_client: APIClient = PrivateAttr()
    _group: Optional[GroupPydanticModel] = PrivateAttr(default=None)
    _logger: logging.Logger = PrivateAttr()

    _projects: Optional[List[ProjectPydanticModel]] = PrivateAttr(default=None)
    _issues: Optional[List[IssuePydanticModel]] = PrivateAttr(default=None)
    _policies: Optional[List[PolicyPydanticModel]] = PrivateAttr(default=None)
    _integrations: Optional[List[Dict[str, Any]]] = PrivateAttr(default=None)

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_api_response(cls,
                          org_data: Dict[str, Any],
                          api_client: APIClient,
                          group: Optional[GroupPydanticModel] = None,
                          fetch_full_details_if_summary: bool = False) -> OrganizationPydanticModel:
        """Creates an OrganizationPydanticModel instance from API response data.

        If only summary data (e.g., just ID) is provided and
        `fetch_full_details_if_summary` is True, it will fetch the full
        organization details.

        Args:
            org_data: The 'data' part of an API item representing an organization.
            api_client: An instance of the APIClient.
            group: The parent GroupPydanticModel instance, if applicable.
            fetch_full_details_if_summary: If True, fetches full details if
                only summary data is provided.

        Returns:
            An initialized OrganizationPydanticModel instance.
        
        Raises:
            ValueError: If `org_data` does not contain an 'id' when
                `fetch_full_details_if_summary` is True and full details are needed.
        """
        logger = api_client.logger

        if fetch_full_details_if_summary and ('attributes' not in org_data or 'relationships' not in org_data):
            org_id_to_fetch = org_data.get('id')
            if not org_id_to_fetch:
                raise ValueError("Organization data must contain an 'id' to fetch full details.")
            logger.debug(f"[Org ID: {org_id_to_fetch}] Summary data provided. Fetching full details...")
            
            uri = f"/rest/orgs/{org_id_to_fetch}"
            headers = {'Content-Type': 'application/json', 'Authorization': f'token {api_client.token}'}
            params = {'version': API_VERSION_ORG}
            try:
                response = api_client.get(uri, headers=headers, params=params)
                full_org_data_response = response.json()
                org_data = full_org_data_response.get('data', org_data)
            except Exception as e:
                logger.error(f"Failed to fetch full details for org {org_id_to_fetch}: {e}")

        instance = cls(**org_data)
        instance._api_client = api_client
        instance._group = group
        instance._logger = logger

        instance._logger.info(f"[Org ID: {instance.id}] Created organization object for '{instance.name}'")

        if API_CONFIG.get("loading_strategy") == "eager":
            instance.fetch_projects()
            instance.fetch_issues()
            instance.fetch_policies()
            instance.fetch_integrations()
            
        return instance

    @property
    def name(self) -> str:
        """The name of the organization."""
        return self.attributes.name

    @property
    def slug(self) -> str:
        """The URL-friendly slug of the organization."""
        return self.attributes.slug

    @property
    def group_id(self) -> Optional[str]:
        """The ID of the group this organization belongs to, if available."""
        if self.relationships and self.relationships.group and self.relationships.group.data:
            return self.relationships.group.data.id
        return None

    @property
    def projects(self) -> List[ProjectPydanticModel]:
        """List of Snyk projects within this organization.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._projects is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_projects()
            else:
                 self._projects = []
        return self._projects if self._projects is not None else []

    @property
    def issues(self) -> List[IssuePydanticModel]:
        """List of issues within this organization.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._issues is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_issues()
            else:
                 self._issues = []
        return self._issues if self._issues is not None else []

    @property
    def policies(self) -> List[PolicyPydanticModel]:
        """List of security policies configured for this organization.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._policies is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_policies()
            else:
                 self._policies = []
        return self._policies if self._policies is not None else []

    @property
    def integrations(self) -> List[Dict[str, Any]]:
        """List of integrations configured for this organization (uses Snyk API v1).
        
        Fetched lazily or eagerly based on SDK configuration.
        Data structure is a list of dictionaries due to v1 API variability.
        """
        if self._integrations is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_integrations()
            else:
                self._integrations = []
        return self._integrations if self._integrations is not None else []

    def fetch_projects(self, params: Optional[Dict[str, Any]] = None) -> List[ProjectPydanticModel]:
        """Fetches projects for this organization from the Snyk API.

        If projects have already been fetched, returns the cached list.
        Otherwise, makes an API call to retrieve projects. Results are
        cached for subsequent calls.

        Args:
            params: Optional query parameters for the API request.

        Returns:
            A list of `ProjectPydanticModel` instances.
        """
        self._logger.debug(f"[Org ID: {self.id}] Fetching projects...")
        if self._projects is not None:
            return self._projects

        from .project import ProjectPydanticModel

        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/projects"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_ORG, 'limit': 100}
        current_api_params.update(_params)
        
        total_limit = _params.get('limit')
        if total_limit is not None:
            if 'limit' not in current_api_params or total_limit < current_api_params['limit']:
                 current_api_params['limit'] = total_limit
        
        all_project_data_items: List[Dict[str, Any]] = []
        try:
            item_count = 0
            for project_data_item in self._api_client.paginate(
                    endpoint=uri, params=current_api_params, data_key='data', headers=headers):
                all_project_data_items.append(project_data_item)
                item_count += 1
                if total_limit is not None and item_count >= total_limit:
                    self._logger.debug(f"[Org ID: {self.id}] Reached total limit of {total_limit} projects.")
                    break 
        except Exception as e_paginate:
            self._logger.error(f"[Org ID: {self.id}] Error paginating projects: {e_paginate}", exc_info=True)
            self._projects = []
            return self._projects
        
        if not all_project_data_items:
            self._projects = []
            return self._projects
            
        project_futures = []
        for project_data in all_project_data_items:
            future = self._api_client.submit_task(
                ProjectPydanticModel.from_api_response,
                project_data,
                self._api_client,
                self,
                self._group
            )
            project_futures.append(future)

        projects_results: List[ProjectPydanticModel] = []
        for future in concurrent.futures.as_completed(project_futures):
            try:
                project_instance = future.result()
                if project_instance:
                    projects_results.append(project_instance)
            except Exception as e_future:
                self._logger.error(f"[Org ID: {self.id}] Error instantiating Project model: {e_future}", exc_info=True)
                
        self._projects = projects_results
        self._logger.info(f"[Org ID: {self.id}] Fetched and instantiated {len(self._projects)} projects.")
        return self._projects

    def fetch_issues(self, params: Optional[Dict[str, Any]] = None) -> List[IssuePydanticModel]:
        """Fetches issues for this organization from the Snyk API.

        If issues have already been fetched, returns the cached list.
        Otherwise, makes an API call. Results are cached.

        Args:
            params: Optional query parameters for the API request.

        Returns:
            A list of `IssuePydanticModel` instances.
        """
        self._logger.debug(f"[Org ID: {self.id}] Fetching issues...")
        if self._issues is not None:
            return self._issues

        from .issue import IssuePydanticModel

        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/issues"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_ORG, 'limit': 100}
        current_api_params.update(_params)
        
        data_items: List[Dict[str, Any]] = []
        try:
            for data_item in self._api_client.paginate(
                    endpoint=uri, params=current_api_params, data_key='data', headers=headers):
                data_items.append(data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Org ID: {self.id}] Error paginating issues: {e_paginate}", exc_info=True)
            self._issues = []
            return self._issues
        
        if not data_items:
            self._issues = []
            return self._issues
            
        issue_futures = []
        for issue_data in data_items:
            future = self._api_client.submit_task(
                IssuePydanticModel.from_api_response,
                issue_data,
                self._api_client,
                self
            )
            issue_futures.append(future)
            
        issues_results: List[IssuePydanticModel] = []
        for future in concurrent.futures.as_completed(issue_futures):
            try:
                issue_instance = future.result()
                if issue_instance:
                    issues_results.append(issue_instance)
            except Exception as e_future:
                self._logger.error(f"[Org ID: {self.id}] Error instantiating Issue model: {e_future}", exc_info=True)
                
        self._issues = issues_results
        self._logger.info(f"[Org ID: {self.id}] Fetched and instantiated {len(self._issues)} issues.")
        return self._issues

    def fetch_policies(self, params: Optional[Dict[str, Any]] = None) -> List[PolicyPydanticModel]:
        """Fetches security policies for this organization from the Snyk API.

        If policies have already been fetched, returns the cached list.
        Otherwise, makes an API call. Results are cached.

        Args:
            params: Optional query parameters for the API request.

        Returns:
            A list of `PolicyPydanticModel` instances.
        """
        self._logger.debug(f"[Org ID: {self.id}] Fetching policies...")
        if self._policies is not None:
            return self._policies

        from .policy import PolicyPydanticModel

        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/policies"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_ORG, 'limit': 100}
        current_api_params.update(_params)
        
        data_items: List[Dict[str, Any]] = []
        try:
            for data_item in self._api_client.paginate(
                    endpoint=uri, params=current_api_params, data_key='data', headers=headers):
                data_items.append(data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Org ID: {self.id}] Error paginating policies: {e_paginate}", exc_info=True)
            self._policies = []
            return self._policies
            
        if not data_items:
            self._policies = []
            return self._policies
            
        policy_futures = []
        for policy_data in data_items:
            future = self._api_client.submit_task(
                PolicyPydanticModel.from_api_response,
                policy_data,
                self._api_client,
                self
            )
            policy_futures.append(future)
            
        policy_results: List[PolicyPydanticModel] = []
        for future in concurrent.futures.as_completed(policy_futures):
            try:
                policy_instance = future.result()
                if policy_instance:
                    policy_results.append(policy_instance)
            except Exception as e_future:
                self._logger.error(f"[Org ID: {self.id}] Error instantiating Policy model: {e_future}", exc_info=True)
                
        self._policies = policy_results
        self._logger.info(f"[Org ID: {self.id}] Fetched and instantiated {len(self._policies)} policies.")
        return self._policies

    def fetch_integrations(self) -> List[Dict[str, Any]]:
        """Fetches integrations for this organization using the Snyk v1 API.

        If integrations have already been fetched, returns the cached list.
        Otherwise, makes an API call. Results are cached.
        Note: This method uses the Snyk v1 API, and the response structure
        may vary. The results are returned as a list of dictionaries.

        Returns:
            A list of dictionaries, each representing an integration.
        """
        self._logger.debug(f"[Org ID: {self.id}] Fetching integrations (v1 API)...")
        if self._integrations is not None:
            return self._integrations

        uri = f"/v1/org/{self.id}/integrations"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        
        all_integrations_data_items: List[Dict[str, Any]] = []
        try:
            response_obj = self._api_client.get(uri, headers=headers)
            response_json = response_obj.json()

            if isinstance(response_json, dict) and 'org' in response_json and isinstance(response_json['org'], dict):
                 for int_type, int_details in response_json.items():
                     if int_type != 'org':
                         if isinstance(int_details, dict):
                            int_details['type'] = int_type 
                            all_integrations_data_items.append(int_details)
                         elif isinstance(int_details, list):
                            for item_detail in int_details:
                                if isinstance(item_detail, dict):
                                    item_detail['type'] = int_type
                                    all_integrations_data_items.append(item_detail)
            elif isinstance(response_json, list):
                all_integrations_data_items = response_json
            else:
                self._logger.warning(f"[Org ID: {self.id}] Unexpected response format for v1 integrations: {type(response_json)}")
        except Exception as e_fetch:
            self._logger.error(f"[Org ID: {self.id}] Error fetching v1 integrations: {e_fetch}", exc_info=True)
            self._integrations = []
            return self._integrations
            
        self._integrations = all_integrations_data_items
        self._logger.info(f"[Org ID: {self.id}] Fetched {len(self._integrations)} integrations (v1 API).")
        return self._integrations

    def get_specific_project(self, project_id: str, params: Optional[Dict[str, Any]] = None) -> Optional[ProjectPydanticModel]:
        """Fetches a specific project by its ID within this organization.

        Args:
            project_id: The ID of the project to fetch.
            params: Optional query parameters for the API request.

        Returns:
            A `ProjectPydanticModel` instance if found, otherwise `None`.
        """
        self._logger.debug(f"[Org ID: {self.id}] Fetching specific project by ID: {project_id}...")
        from .project import ProjectPydanticModel

        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/projects/{project_id}"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_ORG}
        current_api_params.update(_params)
        
        try:
            response = self._api_client.get(uri, headers=headers, params=current_api_params)
            project_data = response.json().get('data')
            if project_data:
                return ProjectPydanticModel.from_api_response(
                    project_data,
                    self._api_client,
                    self,
                    self._group
                )
            else:
                self._logger.warning(f"[Org ID: {self.id}] No data found for project {project_id}.")
                return None
        except Exception as e:
            self._logger.error(f"[Org ID: {self.id}] Error fetching project {project_id}: {e}", exc_info=True)
            return None
