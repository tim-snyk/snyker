from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Any
if TYPE_CHECKING:
    from .api_client import APIClient
    from .organization import Organization
    from .asset import Asset
    from .project import Project
    from .issue import Issue
from .api_client import APIClient
from .organization import Organization
from .asset import Asset
from .issue import Issue
import json
import logging

api_version_group = "2024-10-15"

class Group:
    """
    Represents a Snyk Group, a top-level organizational unit in Snyk.

    A Group can contain multiple Snyk Organizations and provides a scope for
    managing assets, issues, and policies across those organizations. This class
    provides methods to interact with group-level Snyk API endpoints and to
    retrieve associated entities.

    Attributes:
        id (str): The unique identifier of the Snyk Group.
        name (str): The name of the Snyk Group.
        raw (Dict[str, Any]): The raw JSON data for the group from the Snyk API.
        api_client (APIClient): The API client instance used for Snyk API interactions.
        logger (logging.Logger): Logger instance for this group.
        orgs (List[Organization]): A list of Organization objects belonging to this group.
                                   Populated by the `get_orgs()` method.
        assets (List[Asset]): A list of Asset objects belonging to this group.
                              Populated by the `get_assets()` method.
        issues (List[Issue]): A list of Issue objects within this group's scope.
                              Populated by the `get_issues()` method.
    """
    def __init__(self,
                 group_id: Optional[str] = None,
                 api_client: Optional[APIClient] = None,
                 params: Optional[Dict[str, Any]] = None):
        """
        Initializes a Snyk Group object.

        If `group_id` is not provided, the constructor attempts to find a single
        group associated with the API token. If multiple groups are found,
        a ValueError is raised. If a `group_id` is provided, it fetches data
        for that specific group.

        Args:
            group_id (Optional[str]): The ID of the Snyk Group. If None, attempts
                                      to auto-discover.
            api_client (Optional[APIClient]): An existing APIClient instance.
                                              If None, a new one is created with
                                              default settings.
            params (Optional[Dict[str, Any]]): Additional query parameters to pass when fetching
                                     group data. Used by `get_group_data_by_id` or
                                     `_get_all_groups_data_for_init`. Defaults to None (empty dict).

        Raises:
            ValueError: If `group_id` is None and no groups or multiple groups
                        are found for the token, or if group data initialization fails.
            KeyError: If essential keys are missing from the fetched group data.
        """
        _params = params if params is not None else {}

        self.api_client: APIClient = APIClient(max_retries=15,
                                    backoff_factor=1,
                                    logging_level=20) if api_client is None else api_client
        
        if hasattr(self.api_client, 'logger') and self.api_client.logger:
            self.logger = self.api_client.logger
        else:
            self.logger = logging.getLogger(f"{__name__}.GroupInstance")
            self.logger.warning("APIClient did not have a logger; Group created its own.")

        if group_id is None:
            groups_data = self._get_all_groups_data_for_init(params=_params)
            if len(groups_data) == 1:
                self.raw: Dict[str, Any] = groups_data[0]
                self.id: str = self.raw['id']
            elif len(groups_data) == 0:
                self.logger.error("No groups found for this token.")
                raise ValueError("No groups found for this token.")
            else:
                group_names = [g.get('attributes', {}).get('name', g.get('id', 'Unknown')) for g in groups_data]
                self.logger.error(
                    f"Multiple groups found ({len(groups_data)}: {', '.join(group_names)}). Please specify a group_id or use a Service Account Token."
                )
                raise ValueError(
                    f"Multiple groups found ({len(groups_data)}). Please specify group_id or use a Service Account Token."
                )
        else:
            self.id = group_id
            self.raw = self.get_group_data_by_id(self.id, params=_params)

        if not self.raw or 'attributes' not in self.raw or 'name' not in self.raw['attributes']:
            self.logger.error(f"Failed to initialize group. Raw data incomplete or missing name: {self.raw}")
            raise ValueError(f"Failed to initialize group {self.id}. Raw data incomplete or missing name.")

        self.name: str = self.raw['attributes']['name']
        
        self.orgs: List[Organization] = []
        self.assets: List[Asset] = []
        self.issues: List[Issue] = []
        
        self.logger.info(f"[Group ID: {self.id}] Created group object for '{self.name}'")

    def get_group_data_by_id(self, group_id_to_fetch: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Fetches data for a specific group by its ID from the Snyk API.
        Endpoint: GET /rest/groups/{groupId}

        Args:
            group_id_to_fetch (str): The unique identifier of the group to fetch.
            params (Optional[Dict[str, Any]]): Additional query parameters to include in the API request.
                                     These are merged with default parameters like 'version'.

        Returns:
            Dict[str, Any]: The raw dictionary data for the group, typically the content
                            of the 'data' field in the API response.

        Raises:
            requests.exceptions.HTTPError: If the API request fails.
        """
        _params = params if params is not None else {}
        uri = f"/rest/groups/{group_id_to_fetch}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {'version': api_version_group}
        current_api_params.update(_params)
        response = self.api_client.get(uri, headers=headers, params=current_api_params)
        return response.json().get('data', {})

    def _get_all_groups_data_for_init(self, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Internal helper to fetch all accessible groups data during __init__.
        Uses APIClient.paginate to handle multiple pages of group data.
        Endpoint: GET /rest/groups

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters for fetching groups.

        Returns:
            List[Dict[str, Any]]: A list of raw dictionary data for each accessible group.
        """
        _params = params if params is not None else {}
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {'version': api_version_group, 'limit': 100}
        current_api_params.update(_params)
        
        all_groups_data: List[Dict[str, Any]] = []
        try:
            for group_item_data in self.api_client.paginate(
                endpoint="/rest/groups",
                params=current_api_params,
                headers=headers,
                data_key='data'
            ):
                all_groups_data.append(group_item_data)
        except Exception as e:
            self.logger.error(f"Error fetching groups data during init: {e}", exc_info=True)
        return all_groups_data

    def get_asset(self, asset_id: str, params: Optional[Dict[str, Any]] = None) -> Optional[Asset]:
        """
        Fetches a specific asset by its ID within this group.
        Endpoint: GET /closed-beta/groups/{groupId}/assets/{assetId} (Note: closed-beta)

        Args:
            asset_id (str): The unique identifier of the asset to fetch.
            params (Optional[Dict[str, Any]]): Additional query parameters for the API request.

        Returns:
            Optional[Asset]: An `Asset` object if found, otherwise None.
        """
        _params = params if params is not None else {}
        uri = f"/closed-beta/groups/{self.id}/assets/{asset_id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        request_api_params = {'version': api_version_group}
        request_api_params.update(_params)

        try:
            response = self.api_client.get(uri, headers=headers, params=request_api_params)
            asset_data = response.json().get('data', {})
            if asset_data:
                asset = Asset(asset_data, group=self, api_client=self.api_client)
                self.logger.info(f"[Group ID: {self.id}] Fetched asset '{asset.id}'")
                return asset
            else:
                self.logger.warning(f"[Group ID: {self.id}] No data found for asset {asset_id}.")
                return None
        except Exception as e:
            self.logger.error(f"[Group ID: {self.id}] Error fetching asset {asset_id}: {e}", exc_info=True)
            return None

    def get_assets(self, query: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> List[Asset]:
        """
        Searches for assets within the group using a POST request with a query payload.
        Handles pagination if the API supports it for POST search results (custom logic here).
        Endpoint: POST /closed-beta/groups/{groupId}/assets/search (Note: closed-beta)

        Args:
            query (Dict[str, Any]): The query payload for searching assets.
            params (Optional[Dict[str, Any]]): Additional query parameters for the request URL.

        Returns:
            List[Asset]: A list of `Asset` objects matching the search query.

        Raises:
            ValueError: If the `query` parameter is not provided.
        """
        _params = params if params is not None else {}
        uri = f"/closed-beta/groups/{self.id}/assets/search"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        request_api_params = {'version': api_version_group, 'limit': 100}
        request_api_params.update(_params)

        if not query:
            raise ValueError("Query parameter (dict) is required for get_assets.")
        self.logger.debug(f"[Group ID: {self.id}] Searching assets with query: {json.dumps(query, indent=2)}")
        
        assets_results: List[Asset] = []
        next_page_link: Optional[str] = None
        
        try:
            response_obj = self.api_client.post(uri, headers=headers, params=request_api_params, data=query)
            current_response_json = response_obj.json()

            while True:
                if 'data' in current_response_json:
                    for asset_data in current_response_json.get('data', []):
                        try:
                            assets_results.append(Asset(asset_data, group=self, api_client=self.api_client))
                        except Exception as e_inst:
                            self.logger.error(f"[Group ID: {self.id}] Error instantiating Asset {asset_data.get('id', 'UnknownID')}: {e_inst}", exc_info=True)
                
                next_page_link = current_response_json.get("links", {}).get("next")
                if next_page_link:
                    self.logger.debug(f"Fetching next page of assets: {next_page_link}")
                    response_obj = self.api_client.get(next_page_link, headers=headers)
                    current_response_json = response_obj.json()
                else:
                    break
            
        except Exception as e:
            self.logger.error(f"[Group ID: {self.id}] Error during asset retrieval: {e}", exc_info=True)

        self.assets = assets_results
        self.logger.info(f"[Group ID: {self.id}] Found and instantiated {len(self.assets)} assets from search.")
        return self.assets

    def get_orgs(self, params: Optional[Dict[str, Any]] = None) -> List[Organization]:
        """
        Fetches all organizations within this group using APIClient.paginate.
        The fetched organizations are stored in `self.orgs`.
        Endpoint: GET /rest/groups/{groupId}/orgs

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters for fetching organizations.

        Returns:
            List[Organization]: A list of `Organization` objects.
        """
        _params = params if params is not None else {}
        uri = f"/rest/groups/{self.id}/orgs"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {'version': api_version_group, 'limit': 100}
        current_api_params.update(_params)

        organizations_data_items: List[Dict[str, Any]] = []
        try:
            for org_data_item in self.api_client.paginate(
                endpoint=uri,
                params=current_api_params,
                headers=headers,
                data_key='data'
            ):
                organizations_data_items.append(org_data_item)
        except Exception as e:
            self.logger.error(f"[Group ID: {self.id}] Error paginating organizations: {e}", exc_info=True)
            self.orgs = []
            return []

        instantiated_orgs: List[Organization] = []
        for org_data in organizations_data_items:
            org_id = org_data.get('id')
            if org_id:
                try:
                    instantiated_orgs.append(Organization(org_id=org_id, group=self))
                except Exception as e_inst:
                    self.logger.error(f"[Group ID: {self.id}] Error instantiating Organization {org_id}: {e_inst}", exc_info=True)
            else:
                self.logger.warning(f"[Group ID: {self.id}] Organization data item missing 'id': {org_data}")
        
        self.orgs = instantiated_orgs
        self.logger.info(f"[Group ID: {self.id}] Found and instantiated {len(self.orgs)} organizations.")
        return self.orgs

    def get_issues(self, params: Optional[Dict[str, Any]] = None) -> List[Issue]:
        """
        Fetches all issues within this group's scope using APIClient.paginate.
        The fetched issues are stored in `self.issues`.
        Endpoint: GET /rest/groups/{groupId}/issues

        Args:
            params (Optional[Dict[str, Any]]): Additional query parameters (filters, etc.)
                                     for fetching issues.

        Returns:
            List[Issue]: A list of `Issue` objects.
        """
        _params = params if params is not None else {}
        uri = f"/rest/groups/{self.id}/issues"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {'version': api_version_group, 'limit': 100}
        current_api_params.update(_params)

        issues_data_items: List[Dict[str, Any]] = []
        try:
            for issue_data_item in self.api_client.paginate(
                endpoint=uri,
                params=current_api_params,
                headers=headers,
                data_key='data' 
            ):
                issues_data_items.append(issue_data_item)
        except Exception as e:
            self.logger.error(f"[Group ID: {self.id}] Error paginating issues: {e}", exc_info=True)
            self.issues = []
            return []

        instantiated_issues: List[Issue] = []
        for issue_data in issues_data_items:
            issue_id = issue_data.get('id')
            if issue_id:
                try:
                    instantiated_issues.append(Issue(issue_data=issue_data, group=self))
                except Exception as e_inst:
                    self.logger.error(f"[Group ID: {self.id}] Error instantiating Issue {issue_id}: {e_inst}", exc_info=True)
            else:
                self.logger.warning(f"[Group ID: {self.id}] Issue data item missing 'id': {issue_data}")

        self.issues = instantiated_issues
        self.logger.info(f"[Group ID: {self.id}] Found and instantiated {len(self.issues)} issues with params: {json.dumps(_params)}")
        return self.issues
