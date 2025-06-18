from __future__ import annotations
from typing import List, Optional, Dict, Any, TYPE_CHECKING
import concurrent.futures
import logging
import json

from pydantic import BaseModel, Field, PrivateAttr

from snyker.config import API_CONFIG # For loading_strategy
from .api_client import APIClient
# from .project import ProjectPydanticModel # Circular import
from .issue import IssuePydanticModel
from .policy import PolicyPydanticModel

if TYPE_CHECKING:
    from .project import ProjectPydanticModel
    from .group import GroupPydanticModel

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
    _group: Optional["GroupPydanticModel"] = PrivateAttr(default=None)
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
                          group: Optional["GroupPydanticModel"] = None,
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

    def get_specific_project(self, project_id: str, params: Optional[Dict[str, Any]] = None) -> Optional[ProjectPydanticModel]:
        """Fetches a specific project by its ID within this organization.

        Args:
            project_id: The ID of the project to fetch.
            params: Optional query parameters for the API request.

        Returns:
            A `ProjectPydanticModel` instance if found, otherwise `None`.
        """
        self._logger.debug(f"[Org ID: {self.id}] Fetching specific project by ID: {project_id}...")
        from .project import ProjectPydanticModel # Local import
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

    def fetch_projects(self, params: Optional[Dict[str, Any]] = None) -> List[ProjectPydanticModel]:
        self._logger.debug(f"[Org ID: {self.id}] Fetching projects...")
        from .project import ProjectPydanticModel # Local import
        if self._projects is not None and not params:
            return self._projects

        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/projects"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        # APIClient.paginate will now apply the default page limit if 'limit' is not in _params.
        current_api_params = {'version': API_VERSION_ORG}
        current_api_params.update(_params)

        project_data_items: List[Dict[str, Any]] = []
        try:
            for project_data_item in self._api_client.paginate(
                endpoint=uri, params=current_api_params, headers=headers, data_key='data'):
                project_data_items.append(project_data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Org ID: {self.id}] Error paginating projects: {e_paginate}", exc_info=True)
            if not params: self._projects = []
            return []

        if not project_data_items:
            self._logger.info(f"[Org ID: {self.id}] No projects found for this organization with params: {json.dumps(_params)}.")
            if not params: self._projects = []
            return []

        project_futures = []
        for project_data in project_data_items:
            future = self._api_client.submit_task(
                ProjectPydanticModel.from_api_response,
                project_data,
                self._api_client,
                self,
                self._group
            )
            project_futures.append(future)

        project_results: List[ProjectPydanticModel] = []
        for future in concurrent.futures.as_completed(project_futures):
            try:
                project_instance = future.result()
                if project_instance:
                    project_results.append(project_instance)
            except Exception as e_future:
                self._logger.error(f"[Org ID: {self.id}] Error instantiating Project model: {e_future}", exc_info=True)

        if not params:
            self._projects = project_results

        self._logger.info(f"[Org ID: {self.id}] Fetched and instantiated {len(project_results)} projects with params: {json.dumps(_params)}.")
        return project_results

    def fetch_issues(self, params: Optional[Dict[str, Any]] = None) -> List[IssuePydanticModel]:
        self._logger.debug(f"[Org ID: {self.id}] Fetching issues...")
        from .issue import IssuePydanticModel # Local import
        if self._issues is not None and not params: # If params are provided, always refetch
            return self._issues

        # Actual fetching logic would go here. For now, returning empty list.
        # This method needs to be fully implemented.
        self._issues = [] # Placeholder
        self._logger.info(f"[Org ID: {self.id}] Fetched and instantiated {len(self._issues)} issues.")
        return self._issues

    def fetch_policies(self, params: Optional[Dict[str, Any]] = None) -> List[PolicyPydanticModel]:
        self._logger.debug(f"[Org ID: {self.id}] Fetching policies...")
        from .policy import PolicyPydanticModel # Local import
        if self._policies is not None:
            return self._policies
        
        self._logger.debug(f"[Org ID: {self.id}] Fetching policies...")
        from .policy import PolicyPydanticModel # Local import
        if self._policies is not None and not params: # If params are provided, always refetch
            return self._policies

        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/policies"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        # APIClient.paginate will now apply the default page limit if 'limit' is not in _params.
        current_api_params = {'version': API_VERSION_ORG}
        current_api_params.update(_params)

        policy_data_items: List[Dict[str, Any]] = []
        try:
            for policy_data_item in self._api_client.paginate(
                endpoint=uri, params=current_api_params, headers=headers, data_key='data'):
                policy_data_items.append(policy_data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Org ID: {self.id}] Error paginating policies: {e_paginate}", exc_info=True)
            if not params: self._policies = [] # Cache empty list if it was a general fetch
            return [] # Return empty list on error

        if not policy_data_items:
            self._logger.info(f"[Org ID: {self.id}] No policies found for this organization with params: {json.dumps(_params)}.")
            if not params: self._policies = []
            return []

        policy_futures = []
        for policy_data in policy_data_items:
            future = self._api_client.submit_task(
                PolicyPydanticModel.from_api_response,
                policy_data,
                self._api_client,
                self # Pass the organization instance
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
        
        if not params: # Only cache if it's a general fetch without specific params
            self._policies = policy_results
        
        self._logger.info(f"[Org ID: {self.id}] Fetched and instantiated {len(policy_results)} policies with params: {json.dumps(_params)}.")
        return policy_results

    def fetch_integrations(self, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self._logger.debug(f"[Org ID: {self.id}] Fetching integrations (v1 API)...")
        if self._integrations is not None:
            return self._integrations

        # Actual fetching logic would go here. For now, returning empty list.
        # This method needs to be fully implemented.
        self._integrations = [] # Placeholder
        self._logger.info(f"[Org ID: {self.id}] Fetched {len(self._integrations)} integrations.")
        return self._integrations

OrganizationPydanticModel.update_forward_refs()
