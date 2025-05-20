from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional

if TYPE_CHECKING:
    from snyker import APIClient, Organization, Asset, Project, Issue
from snyker import APIClient
import json

api_version = "2024-10-15"  # Set the API version.


class Group:
    def __init__(self,
                 group_id: str = None,
                 api_client: Optional['APIClient'] = None,
                 params: dict = {}):
        self.api_client = APIClient(max_retries=15,
                                    backoff_factor=1,
                                    logging_level=20) if api_client is None else api_client
        self.logger = self.api_client.logger
        if group_id is None:
            response = self.get_groups()
            if len(response) == 1:
                self.raw = response[0]
            else:
                self.logger.error("Multiple groups found. Please specify a group_id or use a Service Account Token.")
                raise ValueError("Multiple groups found. Please specify group_id or use a Service Account Token.")
        else:
            self.raw = self.get_group(group_id)
        self.id = self.raw['id']
        self.name = self.raw['attributes']['name']
        self.orgs = None
        self.assets = None
        self.issues = None
        self.logger.info(f"[Group ID: {self.id}].__init__ created group object for {self.name}")

    def get_group(self, params: dict = {}) -> dict:
        '''
        # GET /rest/groups/{groupId}?version={apiVersion}
        '''
        uri = f"/rest/groups/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100
        }
        current_params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=current_params
        )
        return response.json()['data']

    def get_groups(self, params: dict = {}) -> [dict]:
        '''
        # GET /rest/groups/{groupId}?version={apiVersion}
        '''
        uri = f"/rest/groups/"
        response = self.api_client.get(
            "/rest/groups",
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'{self.api_client.token}'
            },
            params={
                'version': api_version,
                'limit': 100
            }
        ).json()
        if len(response['data']) == 1:
            self.id = response['data'][0]['id']
        return response['data']

    def get_asset(self, asset_id, params: dict = {}) -> Asset:
        from snyker.asset import Asset
        '''
        # GET /closed-beta/groups/{groupId}/assets/{assetId}?version={apiVersion}
        '''
        uri = f"/closed-beta/groups/{self.id}/assets/{asset_id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': api_version,
        }
        params.update(params)

        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        asset = Asset(response.json()['data'], self)
        self.logger.info(f"[Group ID: {self.id}].get_asset found asset {asset.id}")
        return

    def get_assets(self, query: dict, params: dict = {}) -> list[Asset]:
        from snyker.asset import Asset
        '''
        # POST /closed-beta/groups/{groupId}/assets/search?version={apiVersion}
        '''
        uri = f"/closed-beta/groups/{self.id}/assets/search"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': api_version,
            'limit': 100
        }
        params.update(params)
        if not query:
            raise ValueError("Query parameter is required.")
        self.logger.debug(f"[Group ID: {self.id}].get_assets query: {json.dumps(query, indent=4)}")
        response = self.api_client.post(
            uri,
            headers=headers,
            params=params,
            data=query
        )
        assets = []
        while response.status_code == 200 and 'data' in response.json():
            for asset in response.json()['data']:
                assets.append(Asset(asset, self))
            uri = response.json()["links"].get("next") if "next" in response.json()['links'] else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.assets = assets
        self.logger.info(f"[Group ID: {self.id}].get_assets found {len(assets)} assets")
        return assets

    def get_orgs(self, params: dict = {}) -> list[Organization]:
        from snyker.organization import Organization
        '''
        # GET /rest/groups/{group_id}/orgs
        '''
        uri = f"/rest/groups/{self.id}/orgs"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100,
        }
        current_params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=current_params
        )

        organizations = []
        while response.status_code == 200 and 'data' in response.json():
            for organization in response.json()['data']:
                organizations.append(Organization(org_id=organization['id'], group=self))
            uri = response.json()["links"].get("next") if "next" in response.json()['links'] else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.orgs = organizations
        self.logger.info(f"[Group ID: {self.id}].get_orgs found {len(organizations)} organizations")
        return organizations

    def get_issues(self, params: dict = None) -> list[Issue]:
        from snyker.issue import Issue
        '''
        # GET /rest/groups/{groupId}/issues?version={apiVersion}
        '''
        uri = f"/rest/groups/{self.id}/issues"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100,
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
        self.logger.info(f"[Group: {self.id}].get_issues found {len(self.issues)} issues params:{dict(params)}")
        return issues
