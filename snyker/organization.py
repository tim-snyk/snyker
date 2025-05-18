from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional

if TYPE_CHECKING:
    from .issue import Issue
import os
from group import Group

token = os.getenv('SNYK_TOKEN')  # Set your API token as an environment variable
apiVersion = "2024-10-15"  # Set the API version.

class Organization:
    def __init__(self, org_id, group=None, api_client=None, params: dict = {}):
        if group is None:
            self.group = Group()
        if api_client is None:
            self.api_client = group.api_client
        self.logger = self.api_client.logger
        self.id = org_id
        self.raw = self.getOrg(params=params)
        self.integrations = None
        # Attribute helpers
        self.group_id = self.raw['data']['attributes']['group_id']
        self.name = self.raw['data']['attributes']['name']
        self.slug = self.raw['data']['attributes']['slug']


    def get_issues(self, params: dict = {}) -> list[Issue]:
        from issue import Issue
        '''
        # GET /rest/orgs/{orgId}/issues
        '''
        uri = f"/rest/orgs/{self.id}/issues"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{token}'
        }
        params = {
            'version': apiVersion,
            'limit': 100,
            'scan_item.id': None,               # 'projectId'
            'scan_item.type': None,             # 'project'
            'type': None,                       # 'package_vulnerability', 'license', 'cloud', 'code', 'custom', 'config'
            'updated_before': None,             # '2024-10-15T00:00:00Z'
            'updated_after': None,              # '2024-10-15T00:00:00Z'
            'created_before': None,             # '2024-10-15T00:00:00Z'
            'created_after': None,              # '2024-10-15T00:00:00Z'
            'effective_severity_level': None,   # 'info', 'low', 'medium', 'high', 'critical'
            'status': None,                     # 'open', 'resolved'
            'ignored': None,                    # bool
        }
        params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        issues = response.json()['data']
        while response.status_code == 200 and 'data' in response.json():
            for issue in response.json()['data']:
                issues.extend(issue)
            uri = response.json()["links"].get("next") if "links" in response.json() else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        return issues

    def getOrg(self, params: dict = {}):
        '''
        # GET /rest/orgs/{orgId}?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{token}'
        }
        params = {
            'version': apiVersion,
        }
        params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        return response.json()

    def listIntegrations(self, params: dict = {}) -> List[dict]:
        '''
        # GET https://api.snyk.io/v1/org/{orgId}/integrations
        '''
        uri = f"/v1/org/{self.id}/integrations"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {token}'
        }
        params = {
            'version': apiVersion,
            'limit': 100,
        }
        params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers
        ).json()
        integrations = []
        while response.status_code == 200 and 'data' in response.json():
            for integration in response.json()['data']:
                integrations.append(integration)
            uri = response.json()["links"].get("next") if "links" in response.json() else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.integrations = integrations
        return integrations
