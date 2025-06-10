from __future__ import annotations
from typing import List, Optional, Dict, Any, TYPE_CHECKING
import concurrent.futures
import logging
import json
import time # For testApi

import requests # Used directly in testApi, consider refactoring later

from pydantic import BaseModel, Field, PrivateAttr

from snyker.config import API_CONFIG
from .api_client import APIClient
# from .group import GroupPydanticModel # Circular import
# from .issue import IssuePydanticModel # Moved to TYPE_CHECKING

if TYPE_CHECKING:
    from .group import GroupPydanticModel
    from .organization import OrganizationPydanticModel
    from .issue import IssuePydanticModel

API_VERSION_PROJECT = "2024-10-15"
ORIGIN_URLS = {
    'github': 'https://github.com',
    'github-enterprise': 'https://github.com',
    'gitlab': 'https://gitlab.com',
    'bitbucket-server': 'https://bitbucket.org',
    'bitbucket-cloud': 'https://bitbucket.org',
    'azure-devops': 'https://dev.azure.com',
    'azure-repos': 'https://dev.azure.com',
    'bitbucket-connect-app': 'https://bitbucket.org'
}

class ProjectAttributes(BaseModel):
    """Attributes of a Snyk Project."""
    name: str
    type: Optional[str] = None
    origin: Optional[str] = None
    status: Optional[str] = None
    target_reference: Optional[str] = None
    target_file: Optional[str] = None
    created: Optional[str] = None
    read_only: Optional[bool] = None
    test_frequency: Optional[str] = None
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    branch: Optional[str] = None

class RelationshipData(BaseModel):
    """Generic model for relationship data (ID and type)."""
    id: str
    type: str

class Relationship(BaseModel):
    """Represents a relationship link to another Snyk entity."""
    data: RelationshipData

class ProjectRelationships(BaseModel):
    """Relationships of a Snyk Project to other entities."""
    target: Relationship
    organization: Relationship
    importer: Optional[Relationship] = None
    owner: Optional[Relationship] = None

class ProjectPydanticModel(BaseModel):
    """Represents a Snyk Project.

    Provides methods to access project details, related issues, and trigger
    actions like testing via the Snyk API.

    Attributes:
        id: The unique identifier of the project.
        type: The type of the Snyk entity (should be "project").
        attributes: Detailed attributes of the project.
        relationships: Relationships to other Snyk entities like its target and organization.
    """
    id: str
    type: str
    attributes: ProjectAttributes
    relationships: Optional[ProjectRelationships] = None

    _api_client: APIClient = PrivateAttr()
    _organization: "OrganizationPydanticModel" = PrivateAttr()
    _group: Optional["GroupPydanticModel"] = PrivateAttr(default=None)
    _logger: logging.Logger = PrivateAttr()

    _issues: Optional[List[IssuePydanticModel]] = PrivateAttr(default=None)
    _sarif_data: Optional[Dict[str, Any]] = PrivateAttr(default=None)
    _integration_id: Optional[str] = PrivateAttr(default=None)
    _repo_url: Optional[str] = PrivateAttr(default=None)
    _fetched_integration_details: bool = PrivateAttr(default=False)


    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_api_response(cls,
                          project_data: Dict[str, Any],
                          api_client: APIClient,
                          organization: "OrganizationPydanticModel",
                          group: Optional["GroupPydanticModel"] = None,
                          fetch_full_details_if_summary: bool = False
                          ) -> ProjectPydanticModel:
        """Creates a ProjectPydanticModel instance from API response data.

        If only summary data (e.g., just ID) is provided and
        `fetch_full_details_if_summary` is True, it will fetch the full
        project details.

        Args:
            project_data: The 'data' part of an API item representing a project.
            api_client: An instance of the APIClient.
            organization: The parent OrganizationPydanticModel instance.
            group: The parent GroupPydanticModel instance, if applicable.
            fetch_full_details_if_summary: If True, fetches full details if
                only summary data is provided.

        Returns:
            An initialized ProjectPydanticModel instance.
        
        Raises:
            ValueError: If `project_data` does not contain an 'id' when
                `fetch_full_details_if_summary` is True and full details are needed.
        """
        logger = api_client.logger

        if fetch_full_details_if_summary and ('attributes' not in project_data or 'relationships' not in project_data):
            project_id_to_fetch = project_data.get('id')
            if not project_id_to_fetch:
                raise ValueError("Project data must contain an 'id' to fetch full details.")
            logger.debug(f"[Project ID: {project_id_to_fetch}] Summary data. Fetching full details...")
            
            uri = f"/rest/orgs/{organization.id}/projects/{project_id_to_fetch}"
            headers = {'Content-Type': 'application/json', 'Authorization': f'token {api_client.token}'}
            params = {'version': API_VERSION_PROJECT}
            try:
                response = api_client.get(uri, headers=headers, params=params)
                full_project_data_response = response.json()
                project_data = full_project_data_response.get('data', project_data)
            except Exception as e:
                logger.error(f"Failed to fetch full details for project {project_id_to_fetch}: {e}")
        
        instance = cls(**project_data)
        instance._api_client = api_client
        instance._organization = organization
        instance._group = group
        instance._logger = logger
        instance._logger.info(f"[Project ID: {instance.id}] Created project object for '{instance.name}'")

        if API_CONFIG.get("loading_strategy") == "eager":
            instance.fetch_issues()
            instance._fetch_integration_details()
            
        return instance

    @property
    def name(self) -> str:
        """The name of the project."""
        return self.attributes.name

    @property
    def project_type(self) -> Optional[str]:
        """The type of the project (e.g., "sast", "sca", "iac")."""
        return self.attributes.type

    @property
    def origin(self) -> Optional[str]:
        """The origin of the project (e.g., "github", "cli")."""
        return self.attributes.origin

    @property
    def status(self) -> Optional[str]:
        """The status of the project (e.g., "active", "inactive")."""
        return self.attributes.status

    @property
    def target_reference(self) -> Optional[str]:
        """The target reference, such as a branch name for SCM projects."""
        return self.attributes.target_reference
    
    @property
    def target_id(self) -> Optional[str]:
        """The ID of the target associated with this project."""
        if self.relationships and self.relationships.target and self.relationships.target.data:
            return self.relationships.target.data.id
        return None

    @property
    def integration_id(self) -> Optional[str]:
        """The ID of the Snyk integration associated with this project.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if not self._fetched_integration_details:
            self._fetch_integration_details()
        return self._integration_id

    @property
    def repo_url(self) -> Optional[str]:
        """The repository URL for this project, if applicable.
        
        Constructed based on origin and project name.
        Fetched lazily or eagerly based on SDK configuration.
        """
        if not self._fetched_integration_details:
            self._fetch_integration_details()
        return self._repo_url
        
    @property
    def issues(self) -> List[IssuePydanticModel]:
        """List of issues associated with this project.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._issues is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_issues()
            else:
                 self._issues = []
        return self._issues if self._issues is not None else []

    @property
    def sarif(self) -> Optional[Dict[str, Any]]:
        """SARIF data for the project, typically populated by calling `test_api()`."""
        return self._sarif_data

    def _fetch_integration_details(self) -> None:
        """Internal method to retrieve and set integration ID and repo URL.
        
        This is called by properties `integration_id` and `repo_url` if details
        haven't been fetched yet.
        """
        if self._fetched_integration_details:
            return

        self._logger.debug(f"[Project ID: {self.id}] Fetching integration details...")
        org_integrations = self._organization.integrations

        found_integration = False
        if org_integrations:
            for integration_dict in org_integrations:
                integration_name_from_api = integration_dict.get('name', '').lower()
                project_origin = self.origin
                if project_origin is None:
                    self._logger.debug(f"[Project ID: {self.id}] Origin is None, cannot match integration.")
                    continue
                project_origin_lower = project_origin.lower()
                
                match = (integration_name_from_api == project_origin_lower)
                if not match: # Handle common variations
                    if project_origin_lower == "github-enterprise" and integration_name_from_api == "github enterprise":
                        match = True
                    elif project_origin_lower == "azure-repos" and integration_name_from_api == "azure repos":
                        match = True
                
                if match:
                    self._integration_id = integration_dict.get('id')
                    if self._integration_id and self.origin in ORIGIN_URLS:
                        repo_name_part = self.name.split('(')[0].strip() 
                        self._repo_url = ORIGIN_URLS[self.origin] + '/' + repo_name_part
                    
                    self._logger.info(f"[Project ID: {self.id}] Matched integration for origin '{self.origin}' with ID '{self._integration_id}' and repoUrl '{self._repo_url}'")
                    found_integration = True
                    break
        
        if not found_integration:
            self._logger.warning(f"[Project ID: {self.id}] No matching integration found for origin '{self.origin}'.")
        
        self._fetched_integration_details = True


    def fetch_issues(self, params: Optional[Dict[str, Any]] = None) -> List[IssuePydanticModel]:
        """Fetches issues for this project from the Snyk API.

        If issues have already been fetched, returns the cached list.
        Otherwise, makes an API call. Results are cached.
        Issues are typically fetched via the organization-level endpoint with
        filters applied for this specific project.

        Args:
            params: Optional query parameters for the API request.

        Returns:
            A list of `IssuePydanticModel` instances.
        """
        self._logger.debug(f"[Project ID: {self.id}] Fetching issues...")
        if self._issues is not None:
            return self._issues
        
        # Local import to avoid NameError due to TYPE_CHECKING for OrganizationPydanticModel
        # and its methods which might return/use IssuePydanticModel
        from .issue import IssuePydanticModel

        project_specific_filters = {
            'scan_item.id': self.id,
            'scan_item.type': 'project',
        }
        final_params = {**project_specific_filters, **(params or {})}
        
        issues_from_org = self._organization.fetch_issues(params=final_params)
        
        for issue_instance in issues_from_org:
            issue_instance._project = self
            issue_instance._group = self._group

        self._issues = issues_from_org
        self._logger.info(f"[Project ID: {self.id}] Fetched {len(self._issues)} issues.")
        return self._issues

    def test_api(self, continuous_monitor: bool = False) -> Optional[Dict[str, Any]]:
        """Triggers a Snyk test for this project and retrieves SARIF results.

        This is an experimental API endpoint. This method uses direct `requests`
        calls and includes its own retry and polling logic.

        Args:
            continuous_monitor: Whether to enable continuous monitoring for this test.

        Returns:
            A dictionary containing the SARIF data if successful, otherwise `None`.
        """
        if not self.integration_id or not self.repo_url:
            self._logger.error(f"[Project ID: {self.id}] Missing integrationId or repoUrl for testApi. Cannot proceed.")
            return None

        local_delay = 5
        test_api_version = "2024-10-14~experimental"
        uri = f"{self._api_client.base_url}/rest/orgs/{self._organization.id}/tests?version={test_api_version}"
        
        payload = {
            "data": {
                "type": "test",
                "attributes": {
                    "continuous_monitor": continuous_monitor,
                    "options": {
                        "integration_id": self.integration_id,
                        "repo_url": self.repo_url,
                        "revision": self.target_reference
                    }
                }
            }
        }
        headers = {
            'Content-Type': 'application/vnd.api+json',
            'Authorization': f'token {self._api_client.token}',
        }
        
        in_progress_displayed_flag = False
        response_obj = None

        try:
            while True:
                try:
                    self._logger.debug(f"Posting to testApi: {uri} with payload: {json.dumps(payload)}")
                    response_obj = requests.post(uri, headers=headers, json=payload, timeout=30)
                    response_obj.raise_for_status()
                    self._logger.debug(f"testApi POST successful: {response_obj.status_code}")
                    break
                except requests.exceptions.HTTPError as err:
                    if err.response is not None and err.response.status_code == 429:
                        self._logger.debug(f"Rate limit (429) on testApi POST. Retrying in {local_delay}s. Headers: {err.response.headers}")
                        time.sleep(local_delay)
                        local_delay = min(local_delay * 2, 60)
                    elif err.response is not None:
                        self._logger.error(f"HTTP error on testApi POST: {err.response.status_code} - {err.response.text}", exc_info=True)
                        return None
                    else:
                        self._logger.error(f"Request error on testApi POST (no response object): {err}", exc_info=True)
                        return None
                except requests.exceptions.RequestException as req_err:
                    self._logger.error(f"Generic request error on testApi POST: {req_err}", exc_info=True)
                    return None

            if response_obj and response_obj.status_code == 201:
                polling_uri = response_obj.json().get('links', {}).get('self', {}).get('href')
                if not polling_uri:
                    self._logger.error("testApi POST successful, but no polling link ('links.self.href') found.")
                    return None

                self._logger.debug(f"Polling for test results at: {polling_uri}")
                local_delay = 5
                while True:
                    try:
                        poll_response = requests.get(polling_uri, headers=headers, timeout=30)
                        poll_response.raise_for_status()
                        poll_data = poll_response.json()
                        current_state = poll_data.get('data', {}).get('attributes', {}).get('state')
                        self._logger.debug(f"Polling state: {current_state}")

                        if current_state == 'in_progress':
                            if not in_progress_displayed_flag:
                                self._logger.info(f"SARIF generation in progress for {self.repo_url}...")
                                in_progress_displayed_flag = True
                            time.sleep(local_delay)
                            local_delay = min(local_delay * 2, 30)
                        elif current_state == 'completed':
                            self._logger.info(f"SARIF generation completed for {self.repo_url}.")
                            findings_url = poll_data.get('data',{}).get('attributes',{}).get('findings',[{}])[0].get('findings_url')
                            if not findings_url:
                                self._logger.error("SARIF generation completed, but no findings_url found.")
                                return None
                            
                            self._logger.debug(f"Fetching SARIF from: {findings_url}")
                            sarif_response = requests.get(findings_url, timeout=60)
                            sarif_response.raise_for_status()
                            if sarif_response.content:
                                self._sarif_data = sarif_response.json()
                                self._logger.info("SARIF data fetched and stored.")
                                return self._sarif_data
                            else:
                                self._logger.warning("SARIF findings_url returned empty content.")
                                return None
                        elif current_state in ['failed', 'error']:
                             self._logger.error(f"SARIF generation failed with state: {current_state}. Data: {poll_data}")
                             return None
                        else:
                            self._logger.warning(f"SARIF generation in unknown state: {current_state}. Data: {poll_data}")
                            time.sleep(local_delay)

                    except requests.exceptions.HTTPError as poll_err:
                        if poll_err.response is not None and poll_err.response.status_code == 429:
                            self._logger.debug(f"Rate limit (429) while polling testApi. Retrying in {local_delay}s.")
                            time.sleep(local_delay)
                            local_delay = min(local_delay * 2, 60)
                        elif poll_err.response is not None:
                            self._logger.error(f"HTTP error while polling testApi: {poll_err.response.status_code} - {poll_err.response.text}", exc_info=True)
                            return None
                        else:
                            self._logger.error(f"Request error while polling testApi (no response object): {poll_err}", exc_info=True)
                            return None
                    except requests.exceptions.RequestException as req_err_poll:
                        self._logger.error(f"Generic request error while polling testApi: {req_err_poll}", exc_info=True)
                        return None
                    except Exception as e_poll:
                        self._logger.error(f"Unexpected error during testApi polling: {e_poll}", exc_info=True)
                        return None
            elif response_obj:
                 self._logger.error(f"Initial testApi POST call failed with status {response_obj.status_code}: {response_obj.text}")

        except Exception as e_main:
            self._logger.error(f"An unexpected error occurred in test_api main try block: {e_main}", exc_info=True)
        
        return None

    def get_ignores_v1(self) -> List[Dict[str, Any]]:
        """Fetches ignore rules for the project using Snyk API v1.

        Returns:
            A list of dictionaries, each representing an ignore rule.
        """
        self._logger.debug(f"[Project ID: {self.id}] Fetching ignores (v1 API)...")
        uri = f"/v1/org/{self._organization.id}/project/{self.id}/ignores"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self._api_client.token}'
        }
        ignores: List[Dict[str, Any]] = []
        try:
            response_obj = self._api_client.get(uri, headers=headers)
            response_data = response_obj.json()

            if self.project_type == "sast":
                if response_data:
                    ignores = response_data 
                    self._logger.debug(f"SAST ignores for project {self.id}: {json.dumps(ignores, indent=2)}")
                else:
                    self._logger.info(f"No SAST ignores found for project {self.id} or empty response.")
            else:
                self._logger.debug(f"Ignores for project {self.id} (type: {self.project_type}): {json.dumps(response_data, indent=2)}")
                if isinstance(response_data, list):
                    ignores = response_data
                elif response_data:
                     self._logger.warning(f"get_ignores_v1 for project type '{self.project_type}' received non-list data: {type(response_data)}. Assigning as is.")
                     ignores = [response_data]
                else:
                    self._logger.info(f"No ignores found for project {self.id} (type: {self.project_type}).")
            
        except requests.exceptions.RequestException as e:
            self._logger.error(f"RequestException in get_ignores_v1 for project {self.id}, URL {uri}: {e}", exc_info=True)
        except json.JSONDecodeError as e_json:
            self._logger.error(f"JSONDecodeError in get_ignores_v1 for project {self.id}: {e_json}", exc_info=True)
        except Exception as e:
            self._logger.error(f"Unexpected error in get_ignores_v1 for project {self.id}: {e}", exc_info=True)
            
        return ignores

ProjectPydanticModel.update_forward_refs()
