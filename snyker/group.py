from __future__ import annotations
from typing import List, Dict, Optional, Any, TYPE_CHECKING
import concurrent.futures
import logging
import json

from pydantic import BaseModel, Field, PrivateAttr

from snyker.config import API_CONFIG # For loading_strategy
from .api_client import APIClient
# from .organization import OrganizationPydanticModel # Circular import
from .asset import Asset
from .issue import IssuePydanticModel

if TYPE_CHECKING:
    from .organization import OrganizationPydanticModel

API_VERSION_GROUP = "2024-10-15"

class GroupAttributes(BaseModel):
    """Attributes of a Snyk Group."""
    name: str

class GroupPydanticModel(BaseModel):
    """Represents a Snyk Group.

    Provides methods to access and manage entities within the group, such as
    organizations, assets, and issues.

    Attributes:
        id: The unique identifier of the group.
        type: The type of the Snyk entity (should be "group").
        attributes: Detailed attributes of the group, like its name.
    """
    id: str
    type: str
    attributes: GroupAttributes

    _api_client: APIClient = PrivateAttr()
    _logger: logging.Logger = PrivateAttr()

    _organizations: Optional[List["OrganizationPydanticModel"]] = PrivateAttr(default=None)
    _assets: Optional[List[Asset]] = PrivateAttr(default=None)
    _issues: Optional[List[IssuePydanticModel]] = PrivateAttr(default=None)
    
    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def _fetch_group_data_by_id(cls, group_id: str, api_client: APIClient, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fetches raw data for a specific group by its ID."""
        logger = api_client.logger
        logger.debug(f"Fetching data for group ID: {group_id}")
        uri = f"/rest/groups/{group_id}"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {api_client.token}'}
        current_api_params = {'version': API_VERSION_GROUP, **(params or {})}
        try:
            response = api_client.get(uri, headers=headers, params=current_api_params)
            return response.json().get('data', {})
        except Exception as e:
            logger.error(f"Error fetching group data for ID {group_id}: {e}", exc_info=True)
            raise ValueError(f"Failed to fetch data for group {group_id}.") from e

    @classmethod
    def _fetch_all_groups_data(cls, api_client: APIClient, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetches raw data for all groups accessible by the API token."""
        logger = api_client.logger
        logger.debug("Fetching all accessible groups data...")
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {api_client.token}'}
        current_api_params = {'version': API_VERSION_GROUP, 'limit': 100, **(params or {})}
        
        all_groups_data: List[Dict[str, Any]] = []
        try:
            for group_item_data in api_client.paginate(
                endpoint="/rest/groups", params=current_api_params, headers=headers, data_key='data'):
                all_groups_data.append(group_item_data)
        except Exception as e:
            logger.error(f"Error fetching all groups data: {e}", exc_info=True)
        return all_groups_data

    @classmethod
    def get_instance(cls,
                     api_client: APIClient,
                     group_id: Optional[str] = None,
                     params: Optional[Dict[str, Any]] = None) -> GroupPydanticModel:
        """Factory method to create and initialize a GroupPydanticModel instance.

        If `group_id` is provided, it fetches data for that specific group.
        If `group_id` is None, it attempts to find a single accessible group for the
        provided API token. If multiple groups are found, a ValueError is raised.

        Args:
            api_client: An instance of the APIClient.
            group_id: The optional ID of the Snyk Group to fetch.
            params: Optional query parameters for the API request.

        Returns:
            An initialized GroupPydanticModel instance.

        Raises:
            ValueError: If no group_id is provided and zero or multiple groups
                are found for the token, or if group data is incomplete.
        """
        logger = api_client.logger
        group_data: Optional[Dict[str, Any]] = None

        if group_id:
            group_data = cls._fetch_group_data_by_id(group_id, api_client, params)
        else:
            all_groups = cls._fetch_all_groups_data(api_client, params)
            if len(all_groups) == 1:
                group_data = all_groups[0]
            elif len(all_groups) == 0:
                logger.error("No groups found for this token.")
                raise ValueError("No groups found for this token.")
            else:
                group_names = [g.get('attributes', {}).get('name', g.get('id', 'Unknown')) for g in all_groups]
                logger.error(
                    f"Multiple groups found ({len(all_groups)}: {', '.join(group_names)}). "
                    "Please specify a group_id or use a Service Account Token scoped to a single group."
                )
                raise ValueError(
                    f"Multiple groups found ({len(all_groups)}). Please specify group_id."
                )
        
        if not group_data or 'attributes' not in group_data or 'name' not in group_data['attributes']:
            gid_for_log = group_id or "auto-discovered"
            logger.error(f"Failed to initialize group {gid_for_log}. Raw data incomplete or missing name: {group_data}")
            raise ValueError(f"Failed to initialize group {gid_for_log}. Data incomplete.")

        instance = cls(**group_data)
        instance._api_client = api_client
        instance._logger = logger
        instance._logger.info(f"[Group ID: {instance.id}] Created group object for '{instance.name}'")

        if API_CONFIG.get("loading_strategy") == "eager":
            instance.fetch_organizations()
            instance.fetch_issues()
            
        return instance

    @property
    def name(self) -> str:
        """The name of the Snyk Group."""
        return self.attributes.name

    @property
    def organizations(self) -> List[OrganizationPydanticModel]:
        """List of organizations within this group.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._organizations is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_organizations()
            else:
                 self._organizations = []
        return self._organizations if self._organizations is not None else []
        
    @property
    def issues(self) -> List[IssuePydanticModel]:
        """List of issues at the group level.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._issues is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_issues()
            else:
                 self._issues = []
        return self._issues if self._issues is not None else []

    def fetch_organizations(self, params: Optional[Dict[str, Any]] = None) -> List[OrganizationPydanticModel]:
        """Fetches organizations for this group from the Snyk API.

        If organizations have already been fetched, returns the cached list.
        Otherwise, makes an API call to retrieve organizations. Results are
        cached for subsequent calls.

        Args:
            params: Optional query parameters for the API request.

        Returns:
            A list of `OrganizationPydanticModel` instances.
        """
        self._logger.debug(f"[Group ID: {self.id}] Fetching organizations...")
        if self._organizations is not None:
            return self._organizations

        from .organization import OrganizationPydanticModel # Local import

        _params = params if params is not None else {}
        uri = f"/rest/groups/{self.id}/orgs"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_GROUP, 'limit': 100}
        current_api_params.update(_params)

        org_data_items: List[Dict[str, Any]] = []
        try:
            for org_data_item in self._api_client.paginate(
                endpoint=uri, params=current_api_params, headers=headers, data_key='data'):
                org_data_items.append(org_data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Group ID: {self.id}] Error paginating organizations: {e_paginate}", exc_info=True)
            self._organizations = []
            return self._organizations
        
        if not org_data_items:
            self._organizations = []
            return self._organizations
            
        org_futures = []
        for org_data in org_data_items:
            future = self._api_client.submit_task(
                OrganizationPydanticModel.from_api_response,
                org_data,
                self._api_client,
                self,
                fetch_full_details_if_summary=True
            )
            org_futures.append(future)

        org_results: List[OrganizationPydanticModel] = []
        for future in concurrent.futures.as_completed(org_futures):
            try:
                org_instance = future.result()
                if org_instance:
                    org_results.append(org_instance)
            except Exception as e_future:
                self._logger.error(f"[Group ID: {self.id}] Error instantiating Organization model: {e_future}", exc_info=True)
                
        self._organizations = org_results
        self._logger.info(f"[Group ID: {self.id}] Fetched and instantiated {len(self._organizations)} organizations.")
        return self._organizations

    def fetch_issues(self, params: Optional[Dict[str, Any]] = None) -> List[IssuePydanticModel]:
        """Fetches issues at the group level from the Snyk API.

        If issues have already been fetched (and no new params are provided),
        returns the cached list. Otherwise, makes an API call.

        Args:
            params: Optional query parameters for the API request.

        Returns:
            A list of `IssuePydanticModel` instances.
        """
        self._logger.debug(f"[Group ID: {self.id}] Fetching group-level issues...")
        if self._issues is not None and not params:
            return self._issues

        from .issue import IssuePydanticModel # Local import

        _params = params if params is not None else {}
        uri = f"/rest/groups/{self.id}/issues"
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_GROUP, 'limit': 100}
        current_api_params.update(_params)

        issue_data_items: List[Dict[str, Any]] = []
        try:
            for issue_data_item in self._api_client.paginate(
                endpoint=uri, params=current_api_params, headers=headers, data_key='data'):
                issue_data_items.append(issue_data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Group ID: {self.id}] Error paginating group issues: {e_paginate}", exc_info=True)
            if not params: self._issues = []
            return []
        
        if not issue_data_items:
            if not params: self._issues = []
            return []
            
        issue_futures = []
        for issue_data in issue_data_items:
            future = self._api_client.submit_task(
                IssuePydanticModel.from_api_response,
                issue_data,
                self._api_client,
                group=self
            )
            issue_futures.append(future)
            
        issue_results: List[IssuePydanticModel] = []
        for future in concurrent.futures.as_completed(issue_futures):
            try:
                issue_instance = future.result()
                if issue_instance:
                    issue_results.append(issue_instance)
            except Exception as e_future:
                self._logger.error(f"[Group ID: {self.id}] Error instantiating Issue model: {e_future}", exc_info=True)
        
        if not params:
            self._issues = issue_results
        self._logger.info(f"[Group ID: {self.id}] Fetched and instantiated {len(issue_results)} group issues with params: {json.dumps(_params)}.")
        return issue_results

    def get_specific_asset(self, asset_id: str, params: Optional[Dict[str, Any]] = None) -> Optional[Asset]:
        """Fetches a specific asset by its ID within this group.

        Args:
            asset_id: The ID of the asset to fetch.
            params: Optional query parameters for the API request.

        Returns:
            An `Asset` instance if found, otherwise `None`.
        """
        self._logger.debug(f"[Group ID: {self.id}] Fetching specific asset by ID: {asset_id}...")
        _params = params if params is not None else {}
        uri = f"/closed-beta/groups/{self.id}/assets/{asset_id}"
        from .asset import Asset # Local import
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        request_api_params = {'version': API_VERSION_GROUP}
        request_api_params.update(_params)

        try:
            response = self._api_client.get(uri, headers=headers, params=request_api_params)
            asset_data = response.json().get('data', {})
            if asset_data:
                return Asset.from_api_response(asset_data, api_client=self._api_client, group=self)
            else:
                self._logger.warning(f"[Group ID: {self.id}] No data found for asset {asset_id}.")
                return None
        except Exception as e:
            self._logger.error(f"[Group ID: {self.id}] Error fetching asset {asset_id}: {e}", exc_info=True)
            return None

    def get_assets_by_query(self, query: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> List[Asset]:
        """Searches for assets within the group using a POST request with a query payload.

        Args:
            query: The query payload for the asset search.
            params: Optional query parameters for the API request.

        Returns:
            A list of `Asset` instances matching the query.

        Raises:
            ValueError: If the `query` parameter is not provided.
        """
        self._logger.debug(f"[Group ID: {self.id}] Fetching assets by query: {json.dumps(query)}...")
        _params = params if params is not None else {}
        uri = f"/closed-beta/groups/{self.id}/assets/search"
        from .asset import Asset # Local import
        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        request_api_params = {'version': API_VERSION_GROUP, 'limit': 100}
        request_api_params.update(_params)

        if not query:
            raise ValueError("Query parameter (dict) is required for get_assets_by_query.")
        
        asset_data_items: List[Dict[str, Any]] = []
        try:
            response_obj = self._api_client.post(uri, headers=headers, params=request_api_params, data=query)
            current_response_json = response_obj.json()
            
            while True:
                if 'data' in current_response_json:
                    asset_data_items.extend(current_response_json.get('data', []))
                
                next_page_link = current_response_json.get("links", {}).get("next")
                if next_page_link:
                    self._logger.debug(f"Fetching next page of assets from POST search: {next_page_link}")
                    response_obj = self._api_client.get(next_page_link, headers=headers)
                    current_response_json = response_obj.json()
                else:
                    break
        except Exception as e:
            self._logger.error(f"[Group ID: {self.id}] Error during asset query: {e}", exc_info=True)
            return []

        asset_futures = []
        for asset_data in asset_data_items:
            future = self._api_client.submit_task(
                Asset.from_api_response,
                asset_data,
                self._api_client,
                self
            )
            asset_futures.append(future)

        asset_results: List[Asset] = []
        for future in concurrent.futures.as_completed(asset_futures):
            try:
                asset_instance = future.result()
                if asset_instance:
                    asset_results.append(asset_instance)
            except Exception as e_future:
                self._logger.error(f"[Group ID: {self.id}] Error instantiating Asset model from query: {e_future}", exc_info=True)
        
        self._logger.info(f"[Group ID: {self.id}] Found and instantiated {len(asset_results)} assets from query.")
        return asset_results

    def get_organization_by_id(self, org_id: str) -> Optional[OrganizationPydanticModel]:
        """Fetches a specific organization by its ID.

        Checks if the organization is already loaded within this group instance.
        If not, it attempts to fetch the organization directly via the API.
        It also verifies that the fetched organization belongs to the current group.

        Args:
            org_id: The ID of the organization to fetch.

        Returns:
            An `OrganizationPydanticModel` instance if found and belongs to this group,
            otherwise `None`.
        """
        if self._organizations is not None:
            for org in self._organizations:
                if org.id == org_id:
                    return org
        
        self._logger.debug(f"[Group ID: {self.id}] Organization {org_id} not in cache, fetching directly.")
        from .organization import OrganizationPydanticModel # Local import
        try:
            uri = f"/rest/orgs/{org_id}"
            headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
            params = {'version': API_VERSION_GROUP}
            response = self._api_client.get(uri, headers=headers, params=params)
            org_data = response.json().get('data')
            if org_data:
                org_group_id = org_data.get('relationships',{}).get('group',{}).get('data',{}).get('id')
                if org_group_id == self.id:
                    return OrganizationPydanticModel.from_api_response(org_data, self._api_client, self)
                else:
                    self._logger.warning(f"Org {org_id} fetched but belongs to group {org_group_id}, not {self.id}.")
                    return None
            return None
        except Exception as e:
            self._logger.error(f"[Group ID: {self.id}] Error fetching organization {org_id}: {e}", exc_info=True)
            return None

GroupPydanticModel.update_forward_refs()
