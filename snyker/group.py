from __future__ import annotations

import json
from snyker import APIClient
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .asset import Asset
    from .organization import Organization
    from .issue import Issue

api_version = "2024-10-15"  # Set the API version.

class Group:
    def __init__(self, group_id=None, api_client: APIClient = None, params: dict = {}):
        if api_client is None:
            self.api_client = APIClient(max_retries=15, backoff_factor=1, logging_level=20)
        else:
            self.api_client = api_client
        self.logger = self.api_client.logger
        if group_id is None:
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
            else:
                self.logger.error("Multiple groups found. Please specify a group_id or use a Service Account Token.")
                raise ValueError("Multiple groups found. Please specify group_id or use a Service Account Token.")
        else:
            self.id = group_id

        self.orgs = None
        self.assets = None
        self.issues = None
        self.logger.info(f"[Group ID: {self.id}].__init__ created group object")

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
        asset = response.json()['data']
        return Asset(asset, self)

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

    def get_orgs(self, org_name=None, org_slug=None, params: dict = {}) -> list[Organization]:
        from snyker.organization import Organization
        '''
        # GET /rest/groups/{group_id}/orgs
        '''
        uri = f"/rest/groups/{self.id}/orgs"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': api_version,
            'limit': 100,
            'name': org_name,  # Only return orgs whose name contains this value.
            'slug': org_slug,  # Only return orgs whose slug contains this value.
            'expand': None,  # 'member_role'
        }
        params.update(params)

        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
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
        default = {
            'version': api_version,
            'limit': 100,
        }
        params.update(default)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        issues = []
        while response.status_code == 200 and 'data' in response.json():
            for issue in response.json()['data']:
                issues.append(Issue(issue_data=issue, group=self))
            uri = response.json()["links"].get("next") if "next" in response.json()['links'] else None
            if uri:
                response = self.api_client.get(uri, headers=headers)
            else:
                break
        self.issues = issues
        self.logger.info(f"[Group ID: {self.id}].get_issues found {len(issues)} issues")
        return issues

