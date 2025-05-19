from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional
if TYPE_CHECKING:
    from .group import Group
    from .api_client import APIClient
    from .project import Project
    from .issue import Issue
import os
from snyker import APIClient, Group, Issue

token = os.getenv('SNYK_TOKEN')  # Set your API token as an environment variable
apiVersion = "2024-10-15"  # Set the API version.

class Organization:
    def __init__(self,
                 org_id: str,
                 group: Optional['Group'] = None,
                 api_client: Optional['APIClient'] = None,
                 params: dict = {}):
        self.id = org_id
        self.group = Group() if group is None else group
        self.api_client = self.group.api_client if api_client is None else api_client
        self.logger = self.api_client.logger
        self.raw = self.get_org(params=params)
        self.integrations = None

        # Attribute helpers
        self.group_id = self.raw['data']['attributes']['group_id']
        self.name = self.raw['data']['attributes']['name']
        self.slug = self.raw['data']['attributes']['slug']
        self.logger.info(f"[Org ID: {self.id}].__init__ created organization object for {self.name} ")


    def get_issues(self, params: dict = {}) -> list[Issue]:
        '''
        # GET /rest/orgs/{orgId}/issues
        '''
        uri = f"/rest/orgs/{self.id}/issues"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{token}'
        }
        current_params = {
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
        current_params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=current_params
        )
        issues = []
        while response.status_code in [200, 429] and 'data' in response.json():
            for issue in response.json()['data']:
                issues.append(Issue(issue_data=issue, group=self))
            uri = response.json()["links"].get("next") if "next" in response.json()['links'] else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.issues = issues
        self.logger.info(f"[Org: {self.id}].get_issues found {len(issues)} issues with params:"
                         f"{dict(params)}")
        return issues

    def get_org(self, params: dict = {}) -> dict:
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

    def get_projects(self, params: dict = {}) -> List['Projects']:
        '''
        # GET /rest/orgs/{orgId}/projects?version={apiVersion}
        '''
        from snyker.project import Project
        uri = f"/rest/orgs/{self.id}/projects"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': apiVersion,
            'limit': 100,
            'name': None,  # Only return projects whose name contains this value.
            'type': None,  # Only return projects of this type.
            'expand': None,  # 'all', 'issues', 'dependencies'
        }
        current_params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=current_params
        )
        projects = []
        while response.status_code == 200 and 'data' in response.json():
            for project in response.json()['data']:
                projects.append(Project(project['id'], organization=self, group=self.group))
            uri = response.json()["links"].get("next") if "next" in response.json()['links'] else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.projects = projects
        self.logger.info(f"[Org: {self.id}].get_projects found {len(self.projects)} projects with params:"
                         f"{dict(current_params)}")
        return projects