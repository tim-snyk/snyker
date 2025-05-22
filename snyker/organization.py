from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional, Dict, Any
if TYPE_CHECKING:
    from .group import Group
    from .api_client import APIClient
    from .project import Project
    from .issue import Issue
    from .policy import Policy
import os
from .project import Project
from .issue import Issue
from .policy import Policy
from .api_client import APIClient
import concurrent.futures
import logging
import json

api_version_org = "2024-10-15"

class Organization:
    """
    Represents a Snyk Organization.

    An Organization in Snyk is a workspace that contains projects, issues,
    policies, and integrations. It typically belongs to a Snyk Group.
    This class provides methods to interact with organization-level Snyk API
    endpoints and to retrieve associated entities like projects, issues, etc.

    Attributes:
        id (str): The unique identifier of the Snyk Organization.
        name (str): The name of the Snyk Organization.
        slug (str): The URL-friendly slug for the organization.
        group (Group): The parent Snyk Group object.
        api_client (APIClient): The API client instance for Snyk API interactions.
        raw (Dict[str, Any]): Raw JSON data for the organization from the Snyk API.
        logger (logging.Logger): Logger instance for this organization.
        projects (Optional[List[Project]]): List of projects in this organization.
                                            Populated by `get_projects()`.
        issues (Optional[List[Issue]]): List of issues in this organization.
                                        Populated by `get_issues()`.
        policies (Optional[List[Policy]]): List of policies in this organization.
                                           Populated by `get_policies()`.
        integrations (Optional[List[Dict[str, Any]]]): List of integrations (raw dicts).
                                                       Populated by `get_integrations()`.
        group_id (Optional[str]): The ID of the parent group.
    """
    def __init__(self,
                 org_id: str,
                 group: Optional['Group'] = None,
                 api_client: Optional['APIClient'] = None,
                 params: Optional[Dict[str, Any]] = None):
        """
        Initializes a Snyk Organization object.

        Args:
            org_id (str): The unique identifier of the Snyk Organization.
            group (Optional['Group']): The parent Snyk Group. If not provided,
                                       a default Group instance is created. This requires
                                       the API token to have a default group or be a user token
                                       that can list groups to find a single one.
            api_client (Optional['APIClient']): An existing APIClient instance.
                                                If None, it's derived from the `group`.
                                                If both `group` and `api_client` are provided,
                                                this `api_client` will be preferred.
            params (Optional[Dict[str, Any]]): Additional query parameters to pass when
                                     fetching this organization's details via `get_org()`.
                                     Defaults to None (empty dict).

        Raises:
            KeyError: If essential keys are missing from the fetched organization data.
            ValueError: If group context cannot be established when `group` is None.
            Exception: For other unexpected errors during initialization.
        """
        _params = params if params is not None else {}
        try:
            self.id: str = org_id
            
            if api_client:
                self.api_client: APIClient = api_client
                self.group: Optional[Group] = group
            elif group:
                self.group = group
                self.api_client = group.api_client
            else:
                # Import Group here, only when needed
                from .group import Group
                self.logger = logging.getLogger(f"{__name__}.OrganizationProvisionalLogger")
                self.logger.info(f"Org {org_id}: No Group or APIClient provided, attempting to create default Group.")
                self.group = Group()
                self.api_client = self.group.api_client

            if hasattr(self.api_client, 'logger') and self.api_client.logger:
                 self.logger = self.api_client.logger
            else:
                 self.logger = logging.getLogger(f"{__name__}.OrganizationInstance")
                 self.logger.warning("APIClient did not have a logger; Organization created its own.")

            self.raw: Dict[str, Any] = self.get_org(params=_params)
            
            self.integrations: Optional[List[Dict[str, Any]]] = None
            self.projects: Optional[List[Project]] = None
            self.issues: Optional[List[Issue]] = None
            self.policies: Optional[List[Policy]] = None

            attributes = self.raw.get('data', {}).get('attributes', {})
            self.name: str = attributes['name']
            self.slug: str = attributes['slug']
            
            self.group_id: Optional[str] = None
            if self.group:
                self.group_id = self.group.id
            elif 'relationships' in self.raw.get('data', {}) and \
                 'group' in self.raw['data']['relationships'] and \
                 'data' in self.raw['data']['relationships']['group']:
                self.group_id = self.raw['data']['relationships']['group']['data'].get('id')

        except KeyError as e:
            logger_to_use = getattr(self, 'logger', logging.getLogger(__name__))
            logger_to_use.error(f"KeyError: {e} in organization data for org {org_id}. Raw: {getattr(self, 'raw', 'Not fetched')}")
            raise
        except Exception as e:
            logger_to_use = getattr(self, 'logger', logging.getLogger(__name__))
            logger_to_use.error(f"Unexpected error initializing org {org_id}: {e}. Raw: {getattr(self, 'raw', 'Not fetched')}", exc_info=True)
            raise
        self.logger.debug(f"[Org ID: {self.id}] Created organization object for '{self.name}'")

    def get_org(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Fetches detailed data for this specific organization from the Snyk API.
        Endpoint: GET /rest/orgs/{orgId}

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters for the API request.
                                     These are merged with default parameters like 'version'.

        Returns:
            Dict[str, Any]: The raw JSON response from the API, typically containing
                            a 'data' field with the organization's attributes and
                            relationships.

        Raises:
            requests.exceptions.HTTPError: If the API request fails.
        """
        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {'version': api_version_org}
        current_api_params.update(_params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=current_api_params
        )
        return response.json()

    def get_issues(self, params: Optional[Dict[str, Any]] = None) -> List[Issue]:
        """
        Fetches all issues within this organization, potentially across all its projects.
        Uses APIClient.paginate for handling multiple pages of results.
        Instantiates `Issue` objects, possibly concurrently.
        The fetched issues are stored in `self.issues`.
        Endpoint: GET /rest/orgs/{orgId}/issues

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters (e.g., filters)
                                     for fetching issues.

        Returns:
            List[Issue]: A list of `Issue` objects.
        """
        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/issues"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {
            'version': api_version_org,
            'limit': 100,
        }
        current_api_params.update(_params)
        
        data_items: List[Dict[str, Any]] = []
        self.logger.debug(f"[Org ID: {self.id}] Fetching issues with params: {json.dumps(current_api_params)}")
        try:
            for data_item in self.api_client.paginate(
                    endpoint=uri,
                    params=current_api_params,
                    data_key='data',
                    headers=headers
            ):
                data_items.append(data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Org ID: {self.id}] Error paginating issues: {e_paginate}", exc_info=True)
            self.issues = []
            return []
        
        self.logger.debug(f"[Org ID: {self.id}] Collected {len(data_items)} issue data items.")
        if not data_items:
            self.issues = []
            return []
            
        issue_futures = []
        for issue_data in data_items:
            future = self.api_client.submit_task(
                Issue,
                issue_data=issue_data,
                org=self
            )
            issue_futures.append(future)
            
        issues_results: List[Issue] = []
        self.logger.debug(f"[Org ID: {self.id}] Waiting for {len(issue_futures)} Issue instantiations.")
        for i, future in enumerate(concurrent.futures.as_completed(issue_futures)):
            try:
                issue_instance = future.result()
                if issue_instance:
                    issues_results.append(issue_instance)
                log_identifier = getattr(issue_instance, 'id', 'N/A') if issue_instance else 'None'
                self.logger.debug(f"[Org ID: {self.id}] Completed issue instantiation {i + 1}/{len(issue_futures)}: ID '{log_identifier}'")
            except Exception as e_future:
                self.logger.error(f"[Org ID: {self.id}] Error instantiating issue (task {i + 1}): {e_future}", exc_info=True)
                
        self.issues = issues_results
        self.logger.info(f"[Org ID: {self.id}] Instantiated {len(self.issues)} of {len(data_items)} Issues with params: {json.dumps(_params)}")
        return self.issues

    def get_policies(self, params: Optional[Dict[str, Any]] = None) -> List[Policy]:
        """
        Fetches all policies defined within this organization.
        Uses APIClient.paginate for handling multiple pages of results.
        Instantiates `Policy` objects, possibly concurrently.
        The fetched policies are stored in `self.policies`.
        Endpoint: GET /rest/orgs/{orgId}/policies

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters for fetching policies.

        Returns:
            List[Policy]: A list of `Policy` objects.
        """
        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/policies"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {
            'version': api_version_org,
            'limit': 100,
        }
        current_api_params.update(_params)
        
        data_items: List[Dict[str, Any]] = []
        self.logger.debug(f"[Org ID: {self.id}] Fetching policies with params: {json.dumps(current_api_params)}")
        try:
            for data_item in self.api_client.paginate(
                    endpoint=uri,
                    params=current_api_params,
                    data_key='data',
                    headers=headers
            ):
                data_items.append(data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Org ID: {self.id}] Error paginating policies: {e_paginate}", exc_info=True)
            self.policies = []
            return []
            
        self.logger.debug(f"[Org ID: {self.id}] Collected {len(data_items)} policy data items.")
        if not data_items:
            self.policies = []
            return []
            
        policy_futures = []
        for policy_data in data_items:
            future = self.api_client.submit_task(
                Policy,
                policy_data=policy_data,
                org=self
            )
            policy_futures.append(future)
            
        policy_results: List[Policy] = []
        self.logger.debug(f"[Org ID: {self.id}] Waiting for {len(policy_futures)} Policy instantiations.")
        for i, future in enumerate(concurrent.futures.as_completed(policy_futures)):
            try:
                policy_instance = future.result()
                if policy_instance:
                    policy_results.append(policy_instance)
                log_identifier = getattr(policy_instance, 'id', 'N/A') if policy_instance else 'None'
                self.logger.debug(f"[Org ID: {self.id}] Completed policy instantiation {i + 1}/{len(policy_futures)}: ID '{log_identifier}'")
            except Exception as e_future:
                self.logger.error(f"[Org ID: {self.id}] Error instantiating policy (task {i + 1}): {e_future}", exc_info=True)
                
        self.policies = policy_results
        self.logger.info(f"[Org ID: {self.id}] Instantiated {len(self.policies)} of {len(data_items)} Policies with params: {json.dumps(_params)}")
        return self.policies

    def get_integrations(self) -> List[Dict[str, Any]]:
        """
        Fetches all integrations configured for this organization.
        Note: This method currently returns a list of raw dictionaries as per Snyk API v1.
        The fetched integrations are stored in `self.integrations`.
        Endpoint: GET /v1/org/{orgId}/integrations (Snyk API v1)

        Returns:
            List[Dict[str, Any]]: A list of dictionaries, where each dictionary
                                  represents an integration's raw data.
        """
        uri = f"/v1/org/{self.id}/integrations"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        
        all_integrations_data_items: List[Dict[str, Any]] = []
        self.logger.debug(f"[Org ID: {self.id}] Fetching integrations from {uri}")
        try:
            response_obj = self.api_client.get(uri, headers=headers)
            response_json = response_obj.json()

            if isinstance(response_json, dict) and 'org' in response_json and isinstance(response_json['org'], dict) :
                 all_integrations_data_items = []
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
                self.logger.warning(f"[Org ID: {self.id}] Unexpected response format for integrations: {type(response_json)}")


        except Exception as e_fetch:
            self.logger.error(f"[Org ID: {self.id}] Error fetching integrations: {e_fetch}", exc_info=True)
            self.integrations = []
            return []
            
        self.logger.debug(f"[Org ID: {self.id}] Collected {len(all_integrations_data_items)} integrations data items.")
        self.integrations = all_integrations_data_items
        return self.integrations

    def get_projects(self, params: Optional[Dict[str, Any]] = None) -> List[Project]:
        """
        Fetches all projects within this organization.
        Uses APIClient.paginate for handling multiple pages of results.
        Instantiates `Project` objects, possibly concurrently.
        The fetched projects are stored in `self.projects`.
        Endpoint: GET /rest/orgs/{orgId}/projects

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters for fetching projects.

        Returns:
            List[Project]: A list of `Project` objects.
        """
        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/projects"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {
            'version': api_version_org,
            'limit': 100,
        }
        current_api_params.update(_params)
        
        all_project_data_items: List[Dict[str, Any]] = []
        self.logger.debug(f"[Org ID: {self.id}] Fetching projects with params: {json.dumps(current_api_params)}")
        try:
            for project_data_item in self.api_client.paginate(
                    endpoint=uri,
                    params=current_api_params,
                    data_key='data',
                    headers=headers
            ):
                all_project_data_items.append(project_data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Org ID: {self.id}] Error paginating projects: {e_paginate}", exc_info=True)
            self.projects = []
            return []
            
        self.logger.debug(f"[Org ID: {self.id}] Collected {len(all_project_data_items)} project data items.")
        if not all_project_data_items:
            self.projects = []
            return []
            
        project_futures = []
        for project_data in all_project_data_items:
            project_id = project_data.get('id')
            if not project_id:
                self.logger.warning(f"[Org ID: {self.id}] Project data item missing ID: {project_data}. Skipping.")
                continue

            future = self.api_client.submit_task(
                Project,
                project_id=project_id,
                organization=self,
                group=self.group,
                api_client=self.api_client
            )
            project_futures.append(future)

        projects_results: List[Project] = []
        self.logger.debug(f"[Org ID: {self.id}] Waiting for {len(project_futures)} Project instantiations.")
        for i, future in enumerate(concurrent.futures.as_completed(project_futures)):
            try:
                project_instance = future.result()
                if project_instance:
                    projects_results.append(project_instance)
                log_name = getattr(project_instance, 'name', 'N/A') if project_instance else 'None'
                self.logger.debug(f"[Org ID: {self.id}] Completed project instantiation {i + 1}/{len(project_futures)}: '{log_name}'")
            except Exception as e_future:
                self.logger.error(f"[Org ID: {self.id}] Error instantiating project (task {i + 1}): {e_future}", exc_info=True)
                
        self.projects = projects_results
        self.logger.info(f"[Org ID: {self.id}] Instantiated {len(self.projects)} of {len(all_project_data_items)} Projects.")
        return self.projects

    def get_project(self, project_id: str, params: Optional[Dict[str, Any]] = None) -> Optional[Project]:
        """
        Fetches a specific project by its ID within this organization.
        Endpoint: GET /rest/orgs/{orgId}/projects/{projectId}

        Args:
            project_id (str): The unique identifier of the project to fetch.
            params (Optional[Dict[str, Any]]): Additional query parameters for the API request.

        Returns:
            Optional[Project]: A `Project` object if found and successfully instantiated,
                               otherwise None.
        """
        _params = params if params is not None else {}
        uri = f"/rest/orgs/{self.id}/projects/{project_id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {'version': api_version_org}
        current_api_params.update(_params)
        
        try:
            response = self.api_client.get(
                uri,
                headers=headers,
                params=current_api_params
            )
            project_data = response.json().get('data')
            if project_data:
                return Project(project_id=project_data['id'], organization=self, group=self.group, api_client=self.api_client)
            else:
                self.logger.warning(f"[Org ID: {self.id}] No data found for project {project_id}.")
                return None
        except Exception as e:
            self.logger.error(f"[Org ID: {self.id}] Error fetching project {project_id}: {e}", exc_info=True)
            return None
