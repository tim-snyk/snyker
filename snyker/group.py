import json
from snyker import APIClient

api_version = "2024-10-15"  # Set the API version.



class Group:
    def __init__(self, group_id=None, api_client=None, params: dict = {}):
        self.api_client = APIClient(max_retries=15, backoff_factor=1)
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
                    'limit': 10
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

    def get_asset(self, asset_id, params: dict = {}) -> 'Asset':
        from asset import Asset
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

    def get_assets(self, query: dict, params: dict = {}) -> list['Asset']:
        from asset import Asset
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

    def get_orgs(self, org_name=None, org_slug=None, params: dict = {}) -> list['Organization']:
        from organization import Organization
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

    def get_issues(self, params: dict = None) -> list['Issue']:
        from issue import Issue
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


# Example Usage:
if __name__ == "__main__":
    group = Group(group_id='9365faba-3e72-4fda-9974-267779137aa6',
                  api_client=SnykApiClient(max_retries=15, backoff_factor=1))

    # Example showing how to get all organizations in a group
    group.orgs = group.get_orgs()

    # Example showing how to get issues in a group based on certain url filter parameters
    group.issues = group.get_issues(params={
        "scan_item.id": "d11d314a-2cbd-44b6-82cb-7b9d6a8df6e5",
        "scan_item.type": "project",
        "type": "code",
    })
    test_query = {
        "query": {
            "attributes": {
                "attribute": "type",
                "operator": "equal",
                "values": [
                    "repository"
                ]
            }
        }
    }
    group.assets = group.get_assets(query=test_query)
    exit(0)

    # Example showing how to get all projects from a specific asset
    asset = group.get_asset('661f4490e4407a0906459156b5781e7d')  # Repository Asset
    print(json.dumps(asset.raw, indent=4))
    asset.projects = asset.get_projects()
    for project in asset.projects if asset.projects is not None else []:
        print(json.dumps(project.raw, indent=4))  # Print the raw project data
    print(f"Total Projects: {len(asset.projects)}")


    # Example of showing how to print specific assets of various types
    print(json.dumps(group.get_asset('661f4490e4407a0906459156b5781e7d').raw, indent=4))  # Repository
    print(json.dumps(group.get_asset('350d7498d292db18afa96d48bbd659ce').raw, indent=4))  # Package
    print(json.dumps(group.get_asset('70d329c3d55b10bdc61b92012c6c6c9f').raw, indent=4))  # Container Image
