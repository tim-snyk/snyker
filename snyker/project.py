import os
import requests
import json
import dateutil
import time
from urllib.parse import quote
import traceback
import threading

apiVersion = "2024-10-15"  # Set the API version.

# TODO: Replace with your URLs
originUrls = {
    'github': 'https://github.com',
    'github-enterprise': 'https://github.com',  # May need to be updated to use the enterprise URL
    'gitlab': 'https://gitlab.com',
    'bitbucket-server': 'https://bitbucket.org',  # May need to be updated to use the enterprise URL
    'bitbucket-cloud': 'https://bitbucket.org',
    'azure-devops': 'https://dev.azure.com',
    'azure-repos': 'https://dev.azure.com',
    'bitbucket-connect-app': 'https://bitbucket.org'
}


class Project:
    def __init__(self, project_id, organization, group=None):
        self.group = organization.group
        self.api_client = self.group.api_client
        self.logger = self.api_client.logger
        self.organization = organization
        self.id = project_id
        # Getting project details because listProjectsInOrg does not provide enough metadata
        self.raw = self.getProject()
        self.issues = None
        self.sarif = None

        # Attribute Helpers
        try:
            self.relationships = self.raw['data']['relationships']
            self.name = self.raw['data']['attributes']['name']
            self.type = self.raw['data']['attributes']['type']
            self.targetReference = self.raw['data']['attributes']['target_reference']
            self.origin = self.raw['data']['attributes']['origin']
            self.targetId = self.raw['data']['relationships']['target']['data']['id']
            self.status = self.raw['data']['attributes']['status']

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)

    def getIntegrationId(self) -> str:
        '''
        Helper function to get the integration ID from the project name and enumerated dictionary.
        '''
        self.organization.integrations = self.organization.listIntegrations()
        for key in self.organization.integrations:
            if key == self.origin:
                self.integrationId = self.getIntegrationId()
                if self.origin in originUrls:
                    self.repoUrl = originUrls[self.origin] + '/' + self.name.split('(')[0]
                return self.organization.integrations[key]
        return None

    def getProject(self, params: dict = {}):
        '''
        # GET /rest/orgs/{orgId}/projects/{projectId}?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.organization.id}/projects/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': apiVersion,
        }
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        return response.json()

    def getProjectIssues(self, scanType=None, status=None, include_ignored=None, created_after=None,
                         created_before=None, params: dict = {}):
        from issue import Issue
        '''
        # GET /rest/orgs/{orgId}/issues?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.organization.id}/issues"
        headers = {
            'Content-Type': 'application/vnd.api+json',
            'Authorization': f'{self.api_client.token}',
        }
        params = {
            'version': apiVersion,
            'limit': 100,
            'scan_item.id': None,  # 'projectId'
            'scan_item.type': None,  # 'project'
            'status': status,
            'type': scanType,
            'created_after': created_after,
            'created_before': created_before,
            'ignored': include_ignored
        }
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        issues = []
        while response.status_code in [200, 429]:
            response_json = response.json()
            if "data" in response_json:
                for issue in response_json['data']:
                    # Uncomment print statement to debug
                    issues.append(Issue(issue))
            uri = response_json["links"].get("next") if "links" in response_json else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.issues = issues
        return issues

    def testApi(self, continuous_monitor=False):
        '''
        Experimental API
        POST /orgs/{org_id}/tests?version={apiVersion}
        '''
        localDelay = 5
        apiVersion = "2024-10-14~experimental"
        uri = f"/rest/orgs/{self.organization.id}/tests?version={apiVersion}"
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
        try:
            while True:
                try:
                    response = requests.post(
                        uri,
                        headers=headers,
                        json=payload
                    )
                    break
                except requests.exceptions.HTTPError as err:
                    if response.status_code == 429:  # Too Many Requests
                        self.logger.debug(f"Rate limit exceeded, retrying in {localDelay} seconds...")
                        time.sleep(localDelay)
                        localDelay = min(localDelay * 2, 500)  # Exponential backoff with a maximum delay
                    else:
                        self.logger.error(f"An unexpected error occurred: {err}{response.text}")
                        raise err
            if response.status_code == 201:
                while True:
                    try:
                        uri = response.json()['links']['self']['href']
                        response = requests.get(
                            uri,
                            headers=headers
                        )
                        response.raise_for_status()
                        while response.status_code in [200, 429] and response.json()['data']['attributes'][
                            'state'] == 'in_progress':
                            if response.status_code == 429:
                                self.logger.debug(f"Rate limit exceeded, retrying in {localDelay} seconds...")
                                time.sleep(localDelay)
                                continue
                            response = requests.get(
                                uri,
                                headers=headers
                            )
                            response.raise_for_status()
                            state = response.json()['data']['attributes']['state']
                            # Only want to show this once.
                            if inProgressDisplayedFlag == False:
                                self.logger.debug(f"    SARIF generation {state}: {self.repoUrl}")
                                # Uncomment to make stdout less noisy with polling
                                inProgressDisplayedFlag = True
                            if state == 'completed':
                                print(f"    SARIF generation {state}: {self.repoUrl}")
                                self.logger.debug(f"    SARIF generation {state}: {self.repoUrl}")
                                # Different API, don't need to share rate limit
                                # print(response.json()['data']['attributes']['findings'][0]['findings_url'])
                                response = requests.get(
                                    response.json()['data']['attributes']['findings'][0]['findings_url']
                                )
                                response.raise_for_status()
                                if response.content:
                                    self.sarif = response.json()
                                    return response.json()  # Finally got the SARIF
                        break
                    except requests.exceptions.HTTPError as err:
                        if response.status_code == 429:  # Too Many Requests
                            print(f"Rate limit exceeded, retrying in {localDelay} seconds...")
                            time.sleep(localDelay)
                            localDelay = min(localDelay * 2, 500)  # Exponential backoff with a maximum delay
                        else:
                            raise err

        except requests.exceptions.RequestException as e:
            print(f"Request URL: {uri}")
            print(f"Request Payload: {json.dumps(payload, indent=4)}")
            print(f"Error downloading file: {e}")
            traceback.print_exc()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()

    def getIgnoresV1(self):
        '''
        # GET https://api.snyk.io/v1/org/orgId/project/projectId/ignores
        :return:
        '''
        uri = f"/v1/org/{self.organization.id}/project/{self.id}/ignores"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        ignores = []
        try:
            response = self.api_client.get(
                uri,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            print(f"Request URL: {uri}")
            traceback.print_exc()
            exit(1)
        if self.type == "sast" and response.json():
            ignores = response.json()
            print(json.dumps(response.json(), indent=4))

        # Capturing SCA and SCA-Container types by process of elimination
        excluded_types = ["helmconfig", "armconfig", "cloudconfig", "terraformplan", "terraformconfig",
                          "cloudformationconfig", "k8sconfig"]
        if self.type in excluded_types:
            print("Invalid scan type")
            exit(1)

        if self.type not in excluded_types and not "sast":
            print(f"    {self.type} is not supported for ignore migration")
            exit(1)
            for i in response:
                # iterate over the list of ignores if multiple ignores present in a project
                for j in response[i]:
                    list(j.keys())
                    for k in j.keys():
                        ignores.append(j[k])
        return ignores
