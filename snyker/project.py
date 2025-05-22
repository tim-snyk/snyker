from __future__ import annotations
import requests
import json
import time
import traceback
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from snyker import APIClient, Group, Organization, Issue

apiVersion = "2024-10-15"

originUrls = {
    'github': 'https://github.com',
    'github-enterprise': 'https://github.com',
    'gitlab': 'https://gitlab.com',
    'bitbucket-server': 'https://bitbucket.org',
    'bitbucket-cloud': 'https://bitbucket.org',
    'azure-devops': 'https://dev.azure.com',
    'azure-repos': 'https://dev.azure.com',
    'bitbucket-connect-app': 'https://bitbucket.org'
}


class Project:
    def __init__(self, project_id: str,
                 organization: 'Organization',
                 group: Optional['Group'] = None,
                 api_client: Optional['APIClient'] = None,
                 params: dict = {}) -> None:

        self.id = project_id
        self.organization = organization
        self.group = Group() if group is None else group
        self.api_client = self.group.api_client if api_client is None else api_client
        self.logger = self.api_client.logger
        self.raw = self.get_project_details(params=params)
        self.issues: Optional[List[Issue]] = None
        self.sarif: Optional[dict] = None

        try:
            self.relationships = self.raw['data']['relationships']
            self.name = self.raw['data']['attributes']['name']
            self.type = self.raw['data']['attributes']['type']
            self.targetReference = self.raw['data']['attributes']['target_reference']
            self.origin = self.raw['data']['attributes']['origin']
            self.targetId = self.raw['data']['relationships']['target']['data']['id']
            self.status = self.raw['data']['attributes']['status']
            self.integrationId: Optional[str] = None
            self.repoUrl: Optional[str] = None

        except Exception as e:
            self.logger.error(f"Error initializing Project {project_id}: {e}", exc_info=True)
            print(f"An unexpected error occurred during Project initialization: {e}")
            traceback.print_exc()
            raise

    def get_integration_id(self) -> Optional[str]:
        """
        Retrieves and returns the integration ID for the project's origin.
        It also sets self.integrationId and self.repoUrl on the project instance if found.
        """
        if self.organization.integrations is None:
            self.organization.get_integrations() 

        if self.organization.integrations:
            for integration_dict in self.organization.integrations:
                integration_name_from_api = integration_dict.get('name', '').lower()
                project_origin_lower = self.origin.lower()
                
                match = (integration_name_from_api == project_origin_lower)
                if not match:
                    if project_origin_lower == "github-enterprise" and integration_name_from_api == "github enterprise":
                        match = True
                    elif project_origin_lower == "azure-repos" and integration_name_from_api == "azure repos":
                        match = True
                
                if match:
                    self.integrationId = integration_dict.get('id')
                    if self.integrationId and self.origin in originUrls:
                        repo_name_part = self.name.split('(')[0].strip()
                        self.repoUrl = originUrls[self.origin] + '/' + repo_name_part
                    
                    self.logger.info(f"[Project: {self.id}] Matched integration for origin '{self.origin}' with ID '{self.integrationId}' and repoUrl '{getattr(self, 'repoUrl', 'N/A')}'")
                    return self.integrationId
        
        self.logger.warning(f"[Project: {self.id}] No matching integration found for origin '{self.origin}'. Integrations available: {self.organization.integrations}")
        return None

    def get_project_details(self, params: dict = {}):
        '''
        '''
        uri = f"/rest/orgs/{self.organization.id}/projects/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        request_params = {'version': apiVersion}
        request_params.update(params)
        
        response = self.api_client.get(
            uri,
            headers=headers,
            params=request_params
        )
        return response.json()

    def get_issues(self, params: dict = {}) -> List[Issue]:
        """
        Fetches issues for this project by delegating to the organization.
        :param params: Additional query parameters for fetching issues.
        :return: List of Issue objects.
        """
        project_specific_params = {
            'scan_item.id': self.id,
            'scan_item.type': 'project',
        }
        final_params = {**project_specific_params, **params, 'version': apiVersion, 'limit': 100}
        
        self.issues = self.organization.get_issues(params=final_params)
        return self.issues

    def testApi(self, continuous_monitor=False):
        '''
        Experimental API
        POST /orgs/{org_id}/tests?version={apiVersion}
        '''
        if not self.integrationId or not self.repoUrl:
            self.get_integration_id()
            if not self.integrationId or not self.repoUrl:
                self.logger.error(f"[Project: {self.id}] Missing integrationId or repoUrl for testApi. Cannot proceed.")
                return None

        localDelay = 5
        test_api_version = "2024-10-14~experimental"
        uri = f"{self.api_client.base_url}/rest/orgs/{self.organization.id}/tests?version={test_api_version}"
        
        payload = {
            "data": {
                "type": "test",
                "attributes": {
                    "continuous_monitor": continuous_monitor,
                    "options": {
                        "integration_id": self.integrationId,
                        "repo_url": self.repoUrl,
                        "revision": self.targetReference
                    }
                }
            }
        }
        headers = {
            'Content-Type': 'application/vnd.api+json',
            'Authorization': f'{self.api_client.token}',
        }
        
        inProgressDisplayedFlag = False
        response_obj = None

        try:
            while True:
                try:
                    self.logger.debug(f"Posting to testApi: {uri} with payload: {json.dumps(payload)}")
                    response_obj = requests.post(uri, headers=headers, json=payload)
                    response_obj.raise_for_status()
                    self.logger.debug(f"testApi POST successful: {response_obj.status_code}")
                    break
                except requests.exceptions.HTTPError as err:
                    if err.response is not None and err.response.status_code == 429:
                        self.logger.debug(f"Rate limit (429) on testApi POST. Retrying in {localDelay}s. Headers: {err.response.headers}")
                        time.sleep(localDelay)
                        localDelay = min(localDelay * 2, 60)
                    elif err.response is not None:
                        self.logger.error(f"HTTP error on testApi POST: {err.response.status_code} - {err.response.text}", exc_info=True)
                        return None
                    else:
                        self.logger.error(f"Request error on testApi POST: {err}", exc_info=True)
                        return None
                except requests.exceptions.RequestException as req_err:
                    self.logger.error(f"Generic request error on testApi POST: {req_err}", exc_info=True)
                    return None

            if response_obj and response_obj.status_code == 201:
                polling_uri = response_obj.json().get('links', {}).get('self', {}).get('href')
                if not polling_uri:
                    self.logger.error("testApi POST successful, but no polling link ('links.self.href') found in response.")
                    return None

                self.logger.debug(f"Polling for test results at: {polling_uri}")
                localDelay = 5
                while True:
                    try:
                        poll_response = requests.get(polling_uri, headers=headers)
                        poll_response.raise_for_status()
                        poll_data = poll_response.json()
                        current_state = poll_data.get('data', {}).get('attributes', {}).get('state')
                        self.logger.debug(f"Polling state: {current_state}")

                        if current_state == 'in_progress':
                            if not inProgressDisplayedFlag:
                                self.logger.info(f"SARIF generation in progress for {getattr(self, 'repoUrl', 'N/A')}...")
                                inProgressDisplayedFlag = True
                            time.sleep(localDelay)
                            localDelay = min(localDelay * 2, 30)
                        elif current_state == 'completed':
                            self.logger.info(f"SARIF generation completed for {getattr(self, 'repoUrl', 'N/A')}.")
                            findings_url = poll_data.get('data',{}).get('attributes',{}).get('findings',[{}])[0].get('findings_url')
                            if not findings_url:
                                self.logger.error("SARIF generation completed, but no findings_url found.")
                                return None
                            
                            self.logger.debug(f"Fetching SARIF from: {findings_url}")
                            sarif_response = requests.get(findings_url)
                            sarif_response.raise_for_status()
                            if sarif_response.content:
                                self.sarif = sarif_response.json()
                                self.logger.info("SARIF data fetched and stored in self.sarif.")
                                return self.sarif
                            else:
                                self.logger.warning("SARIF findings_url returned empty content.")
                                return None
                        elif current_state in ['failed', 'error']:
                             self.logger.error(f"SARIF generation failed with state: {current_state}. Data: {poll_data}")
                             return None
                        else:
                            self.logger.warning(f"SARIF generation in unknown state: {current_state}. Data: {poll_data}")
                            time.sleep(localDelay)

                    except requests.exceptions.HTTPError as poll_err:
                        if poll_err.response is not None and poll_err.response.status_code == 429:
                            self.logger.debug(f"Rate limit (429) while polling testApi. Retrying in {localDelay}s.")
                            time.sleep(localDelay)
                            localDelay = min(localDelay * 2, 60)
                        elif poll_err.response is not None:
                            self.logger.error(f"HTTP error while polling testApi: {poll_err.response.status_code} - {poll_err.response.text}", exc_info=True)
                            return None
                        else:
                            self.logger.error(f"Request error while polling testApi: {poll_err}", exc_info=True)
                            return None
                    except Exception as e_poll:
                        self.logger.error(f"Unexpected error during testApi polling: {e_poll}", exc_info=True)
                        return None
            elif response_obj:
                 self.logger.error(f"Initial testApi POST call failed with status {response_obj.status_code}: {response_obj.text}")

        except Exception as e_main:
            self.logger.error(f"An unexpected error occurred in testApi main try block: {e_main}", exc_info=True)
        
        return None

    def getIgnoresV1(self):
        '''
        :return:
        '''
        uri = f"/v1/org/{self.organization.id}/project/{self.id}/ignores"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        ignores = []
        try:
            response_obj = self.api_client.get(uri, headers=headers)
            response_data = response_obj.json()

            if self.type == "sast":
                if response_data:
                    ignores = response_data 
                    self.logger.debug(f"SAST ignores for project {self.id}: {json.dumps(ignores, indent=4)}")
                else:
                    self.logger.info(f"No SAST ignores found for project {self.id} or empty response.")
            else:
                self.logger.warning(f"getIgnoresV1 for non-SAST type '{self.type}' might not be fully parsed. Returning raw response.")
                if response_data:
                    ignores = response_data
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"RequestException in getIgnoresV1 for project {self.id}, URL {uri}: {e}", exc_info=True)
        except Exception as e:
            self.logger.error(f"Unexpected error in getIgnoresV1 for project {self.id}: {e}", exc_info=True)
            
        return ignores
