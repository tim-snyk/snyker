from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional
if TYPE_CHECKING:
    from snyker import APIClient, Group, Organization, Project
from urllib.parse import urlparse
from snyker import APIClient, Group, Organization, Project
import concurrent.futures

api_version = "2024-10-15"  # Set the API version.


class Asset:
    def __init__(self,
                 asset: dict,
                 group: Optional['Group'] = None,
                 api_client: Optional['APIClient'] = None,
                 params: dict = {}):
        self.group = Group() if group is None else group
        self.api_client = self.group.api_client if api_client is None else api_client
        self.logger = self.api_client.logger
        self.organizations: Optional[List[Organization]] = None
        self.projects: Optional[List[Project]] = None


        # string
        self.raw = asset
        self.id = asset['id']
        self.name = asset['attributes']['name']
        self.type = asset['type']

        # dict
        self.asset_class = asset['attributes'].get('class')
        if 'issues_counts' in asset['attributes']:
            self.issues_counts = asset['attributes'].get('issues_counts')

        # list
        self.sources = asset['attributes']['sources']
        self.coverage_controls = asset['attributes'].get('coverage_control')
        if 'snyk' in self.sources:
            self.logger.debug(f"[Asset ID: {self.id}].__init__ found Snyk source, extracting organizations from "
                              f"{self.raw['attributes']['organizations']} ")
            self.organizations = []
            for organization in asset['attributes']['organizations']:
                self.organizations.append(Organization(org_id=organization['id'], group=self.group, params=params))

        # boolean
        self.archived = asset['attributes'].get('archived')

        # app context-specific attributes, requires 3rd party app context integration
        if 'app_context' in asset['attributes']:
            app_context = asset['attributes'].get('app_context', {})
            self.app_name = app_context.get('application', None)
            self.app_catalog_name = app_context.get('catalog_name', None)
            self.app_category = app_context.get('category', None)
            self.app_lifecycle = app_context.get('lifecycle', None)
            self.app_owner = app_context.get('owner', None)
            self.app_source = app_context.get('source', None)
            self.app_title = app_context.get('title', None)

        # type-specific attributes
        if self.type == 'repository':
            self.browse_url = asset['attributes'].get('browse_url')
            if 'github' in asset['attributes']['sources']:
                self.languages = asset['attributes'].get('languages')
                self.tags = asset['attributes'].get('tags')
            self.repository_freshness = asset['attributes'].get('repository_freshness')
        if self.type == 'package':
            self.file_path = asset['attributes'].get('file_path')
            self.repository_url = asset['attributes'].get('repository_url')
        if self.type == 'image':
            self.image_tags = asset['attributes'].get('image_tags')
            self.image_registries = asset['attributes'].get('image_registries')
            self.image_repositories = asset['attributes'].get('image_repositories')
        self.logger.info(f"[Asset ID: {self.id}].__init__ created asset object for {self.name}")

    def githubNameAndOwnerFromUrl(self) -> tuple[str, str]:
        """ Helper function to extract the GitHub name and owner from the browser URL."""
        if not self.browse_url:
            self.logger.warning(f"No browser URL found for asset {self.id}. Cannot extract GitHub Name.")
            return None, None
        url = self.browse_url
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.strip('/').split('/')
        github_name = path_segments[1]
        github_owner = path_segments[0]
        return github_name, github_owner

    def get_projects(self, params: dict = {}) -> list[Project]:
        """
        Get all projects associated with the asset.
        :param params:
        :return:
        """
        from snyker.project import Project
        if 'snyk' not in self.sources:
            self.logger.warning(f"Asset {self.id} does not have a Snyk source. Cannot extract projects.")
            return []
        try:
            projects_related_link = self.raw['relationships']['projects']['links']['related']
        except KeyError:
            self.logger.warning(f"[Asset ID: {self.id}] No 'related' link found for projects in asset data. "
                                f"Raw relationships: {self.raw.get('relationships')}")
            self.projects = []
            return []
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100,
        }
        current_params.update(params)
        all_project_data_items = []
        self.logger.info(f"[Asset ID: {self.id}].get_projects Starting to fetch all project data items from "
                         f"'{projects_related_link}' for concurrent processing with params: {current_params}.")

        try:
            # Use the APIClient's paginate method
            for project_data_item in self.api_client.paginate(
                    endpoint=projects_related_link, # This is the specific URL for this asset's projects
                    params=current_params,
                    data_key='data',  # Snyk API typically returns items in 'data' list
                    headers=headers
            ):
                all_project_data_items.append(project_data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Asset ID: {self.id}].get_projects Error during pagination for projects: {e_paginate}",
                              exc_info=True)
            self.projects = []
            return []

        self.logger.debug(f"[Asset ID: {self.id}].get_projects Collected {len(all_project_data_items)} project data items.")
        if not all_project_data_items:
            self.logger.info(f"[Asset ID: {self.id}].get_projects No project data items found to process.")
            self.projects = []
            return []

        # Ensure organizations are loaded to resolve project's organization
        if self.organizations is None:
            self.logger.info(
                f"[Asset ID: {self.id}].get_projects: Organizations not yet loaded for this asset,"
                f" fetching them first.")
            self.get_orgs()  # Load organizations if not already loaded
        if not self.organizations:
            self.logger.warning(f"[Asset ID: {self.id}].get_projects: No organizations associated with this asset. "
                                "Cannot properly instantiate projects that require an Organization object.")
        project_futures = []
        self.logger.debug(
            f"[Asset ID: {self.id}].get_projects passing {len(all_project_data_items)} Project instantiations to executor.")

        for project_data in all_project_data_items:
            project_id = project_data.get('id')
            if not project_id:
                self.logger.warning(
                    f"[Asset ID: {self.id}] Found project data item without an ID: {project_data}. Skipping.")
                continue

            # Find the corresponding Organization object for this project
            org_id_for_project = project_data.get('attributes', {}).get('organization_id')
            organization_object_for_project = None
            if org_id_for_project and self.organizations:
                organization_object_for_project = next(
                    (org for org in self.organizations if org.id == org_id_for_project), None
                )
            if not organization_object_for_project:
                self.logger.warning(f"[Asset ID: {self.id}] Could not find matching Organization object for project "
                                    f"{project_id} (org_id: {org_id_for_project}). Project may lack full org context.")

            future = self.api_client.submit_task(
                Project,
                project_id=project_id,
                organization=organization_object_for_project,
                group=self.group,
                api_client=self.api_client,
            )
            project_futures.append(future)

        projects_results: List[Project] = []
        self.logger.debug(f"[Asset ID: {self.id}].get_projects Waiting for {len(project_futures)}"
                         f" Project instantiations to complete.")
        for i, future in enumerate(concurrent.futures.as_completed(project_futures)):
            try:
                project_instance = future.result()
                if project_instance:
                    projects_results.append(project_instance)
                log_name = getattr(project_instance, 'name', 'N/A') if project_instance else 'None'
                self.logger.debug(
                    f"[Asset ID: {self.id}].get_projects Completed project instantiation {i + 1}/{len(project_futures)}:"
                    f" {log_name}")
            except Exception as e_future:
                self.logger.error(
                    f"[Asset ID: {self.id}].get_projects Error instantiating a project concurrently (task {i + 1}):"
                    f" {e_future}",
                    exc_info=True)

        self.projects = projects_results
        self.logger.info(
            f"[Asset ID: {self.id}].get_projects successfully instantiated {len(self.projects)} of "
            f"{len(all_project_data_items)} Projects.")
        return self.projects


    def get_orgs(self, params: dict = {}) -> list[Organization]:
        """
        Get all organizations associated with the asset.
        :return:
        """
        from snyker.organization import Organization
        if 'snyk' not in self.sources:
            self.logger.warning(f"Asset {self.id} does not have a Snyk source. Cannot extract organizations.")
            return []
        organizations = []
        for organization in self.raw['attributes']['organizations']:
            organization = Organization(org_id=organization['id'], group=self.group, params=params)
            organizations.append(organization)
        self.organizations = organizations
        self.logger.info(f"[Asset ID: {self.id}].get_orgs found {len(organizations)} organizations")
        return organizations
