import traceback
import requests
from __future__ import annotations
from typing import TYPE_CHECKING, List  # For Python < 3.9 for list[], use List[]

if TYPE_CHECKING:
    from .asset import Asset
    from .organization import Organization
    from .issue import Issue

api_version = "2024-10-15"  # Set the API version.

# This class is used to represent a target in Snyk.
class Project:
    def __init__(self, organization, project_id):
        self.organization = organization
        self.group = organization.group
        self.APIClient = organization.group.api_client
        self.logger = self.APIClient.logger
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
            self.logger.error("KeyError: The project object does not contain the expected keys.")
            exit(1)
        except TypeError:
            self.logger.error("TypeError: The project object is not in the expected format.")
            exit(1)
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)

    def getProject(self, params: dict = {}, api_version=api_version):
        '''
        # GET /rest/orgs/{orgId}/projects/{projectId}?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.organization.id}/projects/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': api_version,
        }
        params.update(params)
        try:
            response = self.api_client.get(
                uri,
                headers=headers,
                params=params
            )
            response.raise_for_status()
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        return response.json()

    def getProjectV1(self):
        '''
        # GET /v1/org/{orgId}/project/{projectId}
        '''
        uri = f"/v1/org/{self.organization.id}/project/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        try:
            response = self.api_client.get(
                uri,
                headers=headers
            )
            response.raise_for_status()
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        return response.json()
