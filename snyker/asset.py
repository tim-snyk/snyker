from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Tuple
if TYPE_CHECKING:
    from .api_client import APIClient
    from .group import Group
    from .organization import Organization
    from .project import Project

from urllib.parse import urlparse
from .api_client import APIClient
from .project import Project
from .organization import Organization
import concurrent.futures
import logging

api_version_asset = "2024-10-15"

class Asset:
    """
    Represents a Snyk Asset, such as a repository, package, or image.

    An Asset object encapsulates data retrieved from the Snyk API for a specific
    asset. It provides methods to access related entities like organizations
    and projects.

    Attributes:
        id (str): The unique identifier of the asset.
        name (str): The name of the asset.
        type (str): The type of asset (e.g., 'repository', 'package').
        raw (dict): The raw JSON data for the asset from the Snyk API.
        api_client (APIClient): The API client instance used for making further API calls.
        group (Optional[Group]): The parent Group object, if this asset is contextualized
                                                     within a group.
        organizations (Optional[List[Organization]]): A list of Organization objects
                                                     associated with this asset. Populated
                                                     by `get_orgs()` or during init if data present.
        projects (Optional[List[Project]]): A list of Project objects associated
                                            with this asset. Populated by `get_projects()`.
        logger (logging.Logger): Logger instance.
    """
    def __init__(self,
                 asset_data: dict,
                 group: Optional['Group'] = None,
                 api_client: Optional['APIClient'] = None,
                 params: Optional[dict] = None):
        """
        Initializes an Asset object.

        One of `group` or `api_client` must be provided to ensure the asset
        has an API context. The constructor parses `asset_data` to populate
        various attributes of the asset.

        Args:
            asset_data (dict): The raw dictionary data for the asset from the Snyk API.
                               This typically comes from a 'data' field in an API response.
            group (Optional['Group']): The parent Group object. If provided, its
                                       `api_client` will be used.
            api_client (Optional['APIClient']): An APIClient instance. Used if `group`
                                                is not provided or if `group` doesn't
                                                have an `api_client`.
            params (Optional[dict]): Additional parameters, primarily used if organizations
                                     are instantiated during asset initialization. Defaults to None,
                                     which becomes an empty dict internally.

        Raises:
            ValueError: If neither `group` nor `api_client` is provided, or if
                        essential keys (id, name, type) are missing from `asset_data`.
        """
        if group is None and api_client is None:
            raise ValueError("Asset must be initialized with either a Group or an APIClient instance.")

        _params = params if params is not None else {}

        self.api_client: APIClient
        if group:
            self.group: Optional['Group'] = group
            self.api_client = group.api_client
        elif api_client:
            self.group = None
            self.api_client = api_client
        
        if hasattr(self.api_client, 'logger') and self.api_client.logger:
            self.logger = self.api_client.logger
        else:
            self.logger = logging.getLogger(f"{__name__}.AssetInstance")
            self.logger.warning("APIClient did not have a logger; Asset created its own.")

        self.organizations: Optional[List[Organization]] = None
        self.projects: Optional[List[Project]] = None
        self.raw = asset_data

        try:
            self.id = asset_data['id']
            attributes = asset_data.get('attributes', {})
            self.name = attributes['name']
            self.type = asset_data['type']
        except KeyError as e:
            self.logger.error(f"Essential key missing in asset_data for asset {asset_data.get('id', 'UnknownID')}: {e}. Data: {asset_data}")
            raise ValueError(f"Asset data missing essential key: {e}") from e

        self.asset_class = attributes.get('class')
        if 'issues_counts' in attributes:
            self.issues_counts = attributes.get('issues_counts')

        self.sources = attributes.get('sources', [])
        self.coverage_controls = attributes.get('coverage_control')
        
        # Instantiate organizations if 'snyk' source and org data present
        if 'snyk' in self.sources and 'organizations' in attributes:
            if self.group is not None:
                self.logger.debug(f"[Asset ID: {self.id}] Found Snyk source, extracting organizations from {attributes['organizations']}")
                self.organizations = []
                for org_payload in attributes.get('organizations', []):
                    if 'id' in org_payload:
                        self.organizations.append(Organization(org_id=org_payload['id'], group=self.group, params=_params))
                    else:
                        self.logger.warning(f"[Asset ID: {self.id}] Organization payload missing 'id': {org_payload}")
            else:
                 self.logger.warning(f"[Asset ID: {self.id}] Snyk source with organizations found, but no Group context to instantiate them.")

        self.archived = attributes.get('archived')

        if 'app_context' in attributes:
            app_context = attributes.get('app_context', {})
            self.app_name = app_context.get('application')
            self.app_catalog_name = app_context.get('catalog_name')
            self.app_category = app_context.get('category')
            self.app_lifecycle = app_context.get('lifecycle')
            self.app_owner = app_context.get('owner')
            self.app_source = app_context.get('source')
            self.app_title = app_context.get('title')

        # Type-specific attributes
        self.browse_url = attributes.get('browse_url')
        if self.type == 'repository':
            if 'github' in self.sources:
                self.languages = attributes.get('languages')
                self.tags = attributes.get('tags')
            self.repository_freshness = attributes.get('repository_freshness')
        elif self.type == 'package':
            self.file_path = attributes.get('file_path')
            self.repository_url = attributes.get('repository_url')
        elif self.type == 'image':
            self.image_tags = attributes.get('image_tags')
            self.image_registries = attributes.get('image_registries')
            self.image_repositories = attributes.get('image_repositories')
        
        self.logger.info(f"[Asset ID: {self.id}] Created asset object for '{self.name}' of type '{self.type}'")

    def githubNameAndOwnerFromUrl(self) -> Optional[Tuple[str, str]]:
        """
        Extracts the GitHub repository name and owner from the asset's browse URL.

        This is a helper function primarily for assets of type 'repository' where
        the `browse_url` attribute points to a GitHub repository.

        Returns:
            Optional[Tuple[str, str]]: A tuple containing (repository_name, owner_name)
                                        if successful, or None if the URL is not present,
                                        not a GitHub URL, or parsing fails.
        """
        if not hasattr(self, 'browse_url') or not self.browse_url:
            self.logger.warning(f"No browser URL found for asset {self.id}. Cannot extract GitHub Name.")
            return None
        
        try:
            parsed_url = urlparse(self.browse_url)
            if 'github.com' not in parsed_url.netloc.lower():
                self.logger.debug(f"Asset {self.id} browse_url '{self.browse_url}' is not a standard GitHub URL.")
                return None
            
            path_segments = parsed_url.path.strip('/').split('/')
            if len(path_segments) >= 2:
                owner_name = path_segments[0]
                repo_name = path_segments[1]
                return repo_name, owner_name
            else:
                self.logger.warning(f"Could not parse owner/repo from path '{parsed_url.path}' for asset {self.id}.")
                return None
        except Exception as e:
            self.logger.error(f"Error parsing GitHub URL '{self.browse_url}' for asset {self.id}: {e}", exc_info=True)
            return None

    def get_projects(self, params: Optional[dict] = None) -> List[Project]:
        """
        Fetches and instantiates all Snyk Project objects associated with this asset.

        This method uses the 'related' link for projects from the asset's raw data
        and paginates through the results. Project instantiation may be done concurrently.
        The fetched projects are stored in `self.projects`.

        Args:
            params (Optional[dict]): Additional query parameters to pass to the Snyk API
                                     when fetching project data. These are merged with
                                     default parameters like version and limit.

        Returns:
            List[Project]: A list of Project objects associated with this asset.
                           Returns an empty list if no projects are found or if the
                           asset is not from a 'snyk' source.
        """
        _params = params if params is not None else {}

        if 'snyk' not in self.sources:
            self.logger.warning(f"Asset {self.id} does not have a Snyk source. Cannot extract projects.")
            self.projects = []
            return []
        
        try:
            projects_related_link = self.raw['relationships']['projects']['links']['related']
        except KeyError:
            self.logger.warning(f"[Asset ID: {self.id}] No 'related' link found for projects in asset data. Raw relationships: {self.raw.get('relationships')}")
            self.projects = []
            return []

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {self.api_client.token}'
        }
        current_api_params = {
            'version': api_version_asset,
            'limit': 100,
        }
        current_api_params.update(_params)
        
        all_project_data_items = []
        self.logger.info(f"[Asset ID: {self.id}] Fetching project data from '{projects_related_link}' with params: {current_api_params}.")

        try:
            for project_data_item in self.api_client.paginate(
                    endpoint=projects_related_link,
                    params=current_api_params,
                    data_key='data',
                    headers=headers
            ):
                all_project_data_items.append(project_data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Asset ID: {self.id}] Error paginating projects: {e_paginate}", exc_info=True)
            self.projects = []
            return []

        self.logger.debug(f"[Asset ID: {self.id}] Collected {len(all_project_data_items)} project data items.")
        if not all_project_data_items:
            self.projects = []
            return []

        if self.organizations is None:
            self.logger.info(f"[Asset ID: {self.id}] Organizations not loaded, fetching them for project context.")
            self.get_orgs(_params)
        
        project_futures = []
        for project_data in all_project_data_items:
            project_id = project_data.get('id')
            if not project_id:
                self.logger.warning(f"[Asset ID: {self.id}] Project data item missing ID: {project_data}. Skipping.")
                continue

            org_id_for_project = project_data.get('relationships', {}).get('organization', {}).get('data', {}).get('id')
            if not org_id_for_project:
                 org_id_for_project = project_data.get('attributes', {}).get('organization_id')


            organization_object_for_project = None
            if org_id_for_project and self.organizations:
                organization_object_for_project = next((org for org in self.organizations if org.id == org_id_for_project), None)
            
            if not organization_object_for_project:
                self.logger.warning(f"[Asset ID: {self.id}] Could not find Organization object for project {project_id} (org_id: {org_id_for_project}). Project may lack full org context.")

            future = self.api_client.submit_task(
                Project,
                project_id=project_id,
                organization=organization_object_for_project,
                group=self.group,
                api_client=self.api_client
            )
            project_futures.append(future)

        projects_results: List[Project] = []
        self.logger.debug(f"[Asset ID: {self.id}] Waiting for {len(project_futures)} Project instantiations.")
        for i, future in enumerate(concurrent.futures.as_completed(project_futures)):
            try:
                project_instance = future.result()
                if project_instance:
                    projects_results.append(project_instance)
                log_name = getattr(project_instance, 'name', 'N/A') if project_instance else 'None'
                self.logger.debug(f"[Asset ID: {self.id}] Completed project instantiation {i + 1}/{len(project_futures)}: {log_name}")
            except Exception as e_future:
                self.logger.error(f"[Asset ID: {self.id}] Error instantiating project (task {i + 1}): {e_future}", exc_info=True)

        self.projects = projects_results
        self.logger.info(f"[Asset ID: {self.id}] Instantiated {len(self.projects)} of {len(all_project_data_items)} Projects.")
        return self.projects

    def get_orgs(self, params: Optional[dict] = None) -> List[Organization]:
        """
        Retrieves or instantiates Organization objects associated with this asset.

        If the asset's raw data (`self.raw`) contains organization information
        (typically under `attributes.organizations` for 'snyk' sourced assets),
        this method instantiates `Organization` objects for each.
        The instantiated organizations are stored in `self.organizations`.

        Args:
            params (Optional[dict]): Additional parameters to pass to the
                                     `Organization` constructor if they are
                                     instantiated. Defaults to None (empty dict).

        Returns:
            List[Organization]: A list of `Organization` objects. Returns an
                                empty list if no organizations are found or if
                                the asset is not from a 'snyk' source with
                                organization data.
        """
        _params = params if params is not None else {}

        if self.organizations is not None:
            return self.organizations

        if 'snyk' not in self.sources or 'organizations' not in self.raw.get('attributes', {}):
            self.logger.info(f"Asset {self.id} not a 'snyk' source or no 'organizations' attribute. Cannot extract orgs directly.")
            self.organizations = []
            return []
        
        instantiated_organizations = []
        org_payloads = self.raw.get('attributes', {}).get('organizations', [])
        
        if not self.group:
            self.logger.warning(f"[Asset ID: {self.id}] Cannot instantiate organizations as asset has no parent Group context.")
            self.organizations = []
            return []

        for org_data in org_payloads:
            org_id = org_data.get('id')
            if org_id:
                try:
                    org_instance = Organization(org_id=org_id, group=self.group, params=_params)
                    instantiated_organizations.append(org_instance)
                except Exception as e:
                    self.logger.error(f"[Asset ID: {self.id}] Failed to instantiate Organization {org_id}: {e}", exc_info=True)
            else:
                self.logger.warning(f"[Asset ID: {self.id}] Organization data missing 'id': {org_data}")
        
        self.organizations = instantiated_organizations
        self.logger.info(f"[Asset ID: {self.id}] Found and instantiated {len(self.organizations)} organizations.")
        return self.organizations
