from __future__ import annotations
from urllib.parse import urlparse
from typing import TYPE_CHECKING, List, Dict, Optional
if TYPE_CHECKING:
    from .project import Project

api_version = "2024-10-15"  # Set the API version.

class Asset:
    def __init__(self, asset, group=None):
        if group is None:
            from group import Group
            self.group = Group()
        self.group = group
        self.api_client = group.api_client
        self.logger = self.api_client.logger
        self.projects = None

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
            self.organizations = asset['attributes']['organizations']

        # boolean
        self.archived = asset['attributes'].get('archived')

        # app context-specific attributes, requires 3rd party app context integration
        if 'app_context' in asset['attributes']:
            app_context = asset['attributes'].get('app_context', {})
            self.app_name = app_context.get('application')
            self.app_catalog_name = app_context.get('catalog_name')
            self.app_category = app_context.get('category')
            self.app_lifecycle = app_context.get('lifecycle')
            self.app_owner = app_context.get('owner')
            self.app_source = app_context.get('source')
            self.app_title = app_context.get('title')

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
        from project import Project
        from organization import Organization
        if 'snyk' not in self.sources:
            self.logger.warning(f"Asset {self.id} does not have a Snyk source. Cannot extract projects.")
            return None
        projects = []
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': api_version,
            'limit': 100,
        }
        params.update(params)
        response = self.api_client.get(
            self.raw['relationships']['projects']['links']['related'],
            headers=headers,
            params=params,
        ).json()
        for project in response['data']:
            project = Project(organization=Organization(org_id=project['attributes']['organization_id'],
                                                        group=self.group),
                              project_id=project['id'],
                              group=self.group)
            projects.append(project)
        self.projects = projects
        return projects
