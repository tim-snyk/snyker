import traceback
import requests
import datetime

from .api_client import SnykApiClient


class Project:
    def __init__(self, organization, project_id):
        self.organization = organization
        self.id = project_id
        # Getting project details because listProjectsInOrg does not provide enough metadata
        project = self.getProject()
        projectv1 = self.getProjectV1()
        try:
            self.name = project['data']['attributes']['name']
            self.type = project['data']['attributes']['type']
            self.target_reference = project['data']['attributes']['target_reference']
            self.origin = project['data']['attributes']['origin']
            self.target_id = project['data']['relationships']['target']['data']['id']
            self.status = project['data']['attributes']['status']
            self.created_at = project['data']['attributes']['created']
            self.last_tested = projectv1['lastTestedDate']
            self.test_frequency = projectv1['testFrequency']

        except KeyError:
            print(f"Project {project_id} not found in organization {organization.id}")
            exit(1)

    def printProject(self):
        print(f"    Project ID: {self.id}")
        print(f"        Project Name: {self.name}")
        print(f"        Project Type: {self.type}")
        print(f"        Target Reference: {self.target_reference}")
        print(f"        Origin: {self.origin}")
        print(f"        Target ID: {self.target_id}")
        print(f"        Status: {self.status}")
        print(f"        Created At: {self.created_at}")
        print(f"        Age: {datetime.datetime.now() - datetime.datetime.strptime(self.created_at, '%Y-%m-%dT%H:%M:%S.%fZ')}")
        print(f"        Last Tested: {self.last_tested}")
        print(f"        Test Frequency: {self.test_frequency}")
        print(f"        Time since last test: {datetime.datetime.now() - datetime.datetime.strptime(self.last_tested, '%Y-%m-%dT%H:%M:%S.%fZ')}")

    def getProject(self):
        '''
        # GET /rest/orgs/{orgId}/projects/{projectId}?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.organization.id}/projects/{self.id}?version={apiVersion}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            print(f"Request URL: {url + uri}")
            traceback.print_exc()
            exit(1)
        # Uncomment print statement to debug
        # print(json.dumps(response.json(), indent=4))

        return response.json()

    def getProjectV1(self):
        '''
        # GET /v1/org/{orgId}/project/{projectId}
        '''
        uri = f"/v1/org/{self.organization.id}/project/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            print(f"Request URL: {url + uri}")
            traceback.print_exc()
            exit(1)
        # Uncomment print statement to debug
        # print(json.dumps(response.json(), indent=4))

        return response.json()