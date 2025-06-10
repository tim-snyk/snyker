from __future__ import annotations
from typing import List, Dict, Optional, Any, Tuple, TYPE_CHECKING

from pydantic import BaseModel, Field, PrivateAttr
from urllib.parse import urlparse
import concurrent.futures
import logging

from snyker.config import API_CONFIG # For loading_strategy
from .api_client import APIClient
# from .group import GroupPydanticModel # Circular import
from .organization import OrganizationPydanticModel
from .project import ProjectPydanticModel

if TYPE_CHECKING:
    from .group import GroupPydanticModel

API_VERSION_ASSET = "2024-10-15"

class AssetAttributes(BaseModel):
    """Attributes of a Snyk asset."""
    name: str
    class_data: Optional[Dict[str, Any]] = Field(default=None, alias="class")
    issues_counts: Optional[Dict[str, int]] = None
    sources: List[str] = Field(default_factory=list)
    coverage_control: Optional[List[Dict[str, Any]]] = None
    archived: Optional[bool] = None
    app_context: Optional[Dict[str, Any]] = None
    browse_url: Optional[str] = None
    
    # Type-specific attributes
    languages: Optional[Dict[str, int]] = None
    tags: Optional[List[str]] = None
    repository_freshness: Optional[str] = None
    file_path: Optional[str] = None
    repository_url: Optional[str] = None
    image_tags: Optional[List[str]] = None
    image_registries: Optional[List[str]] = None
    image_repositories: Optional[List[str]] = None

    # Captures 'organizations' list if part of asset attributes.
    organizations_payload: Optional[List[Dict[str, Any]]] = Field(default=None, alias="organizations")


    @property
    def app_name(self) -> Optional[str]:
        """The application name from app_context, if available."""
        return self.app_context.get("application") if self.app_context else None

    @property
    def app_catalog_name(self) -> Optional[str]:
        """The application catalog name from app_context, if available."""
        return self.app_context.get("catalog_name") if self.app_context else None
    
    @property
    def app_category(self) -> Optional[str]:
        """The application category from app_context, if available."""
        return self.app_context.get("category") if self.app_context else None

    @property
    def app_lifecycle(self) -> Optional[str]:
        """The application lifecycle stage from app_context, if available."""
        return self.app_context.get("lifecycle") if self.app_context else None

    @property
    def app_owner(self) -> Optional[str]:
        """The application owner from app_context, if available."""
        return self.app_context.get("owner") if self.app_context else None

    @property
    def app_source(self) -> Optional[str]:
        """The application source from app_context, if available."""
        return self.app_context.get("source") if self.app_context else None

    @property
    def app_title(self) -> Optional[str]:
        """The application title from app_context, if available."""
        return self.app_context.get("title") if self.app_context else None


class AssetRelationshipsProjectsLink(BaseModel):
    """Link to related projects for an asset."""
    related: Optional[str] = None

class AssetRelationshipsProjects(BaseModel):
    """Project relationships for an asset."""
    links: Optional[AssetRelationshipsProjectsLink] = None

class AssetRelationships(BaseModel):
    """Relationships of a Snyk asset."""
    projects: Optional[AssetRelationshipsProjects] = None

class Asset(BaseModel):
    """Represents a Snyk asset.

    Attributes:
        id: The unique identifier of the asset.
        type: The type of the asset (e.g., 'repository', 'package').
        attributes: Detailed attributes of the asset.
        relationships: Relationships to other Snyk entities.
    """
    id: str
    type: str
    attributes: AssetAttributes
    relationships: Optional[AssetRelationships] = None

    _api_client: APIClient = PrivateAttr()
    _group: Optional[GroupPydanticModel] = PrivateAttr(default=None)
    _logger: logging.Logger = PrivateAttr()

    _organizations: Optional[List[OrganizationPydanticModel]] = PrivateAttr(default=None)
    _projects: Optional[List[ProjectPydanticModel]] = PrivateAttr(default=None)
    
    class Config:
        arbitrary_types_allowed = True


    @classmethod
    def from_api_response(cls,
                          asset_data: Dict[str, Any],
                          api_client: APIClient,
                          group: Optional[GroupPydanticModel] = None) -> Asset:
        """Creates an Asset instance from API response data.

        Args:
            asset_data: The 'data' part of an API item representing an asset.
            api_client: An instance of the APIClient.
            group: The parent GroupPydanticModel instance, if applicable.

        Returns:
            An instance of Asset.
        """
        instance = cls(**asset_data)
        instance._api_client = api_client
        instance._group = group
        instance._logger = api_client.logger

        instance._logger.info(f"[Asset ID: {instance.id}] Created asset object for '{instance.name}' type '{instance.type}'")

        if API_CONFIG.get("loading_strategy") == "eager":
            instance.fetch_orgs_from_attributes()
            instance.fetch_projects_via_relationship()
            
        return instance

    @property
    def name(self) -> str:
        """The name of the asset."""
        return self.attributes.name

    @property
    def organizations(self) -> List[OrganizationPydanticModel]:
        """List of organizations associated with this asset.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._organizations is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_orgs_from_attributes()
            else:
                 self._organizations = []
        return self._organizations if self._organizations is not None else []
        
    @property
    def projects(self) -> List[ProjectPydanticModel]:
        """List of Snyk projects related to this asset.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._projects is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self.fetch_projects_via_relationship()
            else:
                 self._projects = []
        return self._projects if self._projects is not None else []

    def fetch_orgs_from_attributes(self, params: Optional[Dict[str, Any]] = None) -> List[OrganizationPydanticModel]:
        """Instantiates Organization models from organization data embedded in the Asset's attributes.

        This method relies on the 'organizations_payload' (aliased from 'attributes.organizations')
        field within the asset's attributes. It is typically called during lazy loading or
        eager loading initialization.

        Args:
            params: Optional parameters (currently unused but kept for future compatibility).

        Returns:
            A list of OrganizationPydanticModel instances.
        """
        self._logger.debug(f"[Asset ID: {self.id}] Instantiating organizations from asset attributes...")
        from .organization import OrganizationPydanticModel # Local import
        
        if self._organizations is not None:
            return self._organizations

        instantiated_organizations: List[OrganizationPydanticModel] = []
        
        if 'snyk' not in self.attributes.sources:
            self._logger.info(f"Asset {self.id} not a 'snyk' source. No organizations to instantiate from asset attributes.")
            self._organizations = []
            return self._organizations

        org_payloads = self.attributes.organizations_payload or []

        if not self._group:
            self._logger.warning(f"[Asset ID: {self.id}] Cannot instantiate orgs as asset has no parent Group context.")
            self._organizations = []
            return self._organizations

        org_futures = []
        for org_data in org_payloads:
            org_id = org_data.get('id')
            if org_id:
                future = self._api_client.submit_task(
                    OrganizationPydanticModel.from_api_response, 
                    org_data, 
                    self._api_client,
                    self._group,
                    fetch_full_details_if_summary=True
                )
                org_futures.append(future)
            else:
                self._logger.warning(f"[Asset ID: {self.id}] Org data in asset attributes missing 'id': {org_data}")

        for future in concurrent.futures.as_completed(org_futures):
            try:
                org_instance = future.result()
                if org_instance:
                    instantiated_organizations.append(org_instance)
            except Exception as e_future:
                self._logger.error(f"[Asset ID: {self.id}] Error instantiating Org model from asset attr: {e_future}", exc_info=True)

        self._organizations = instantiated_organizations
        self._logger.info(f"[Asset ID: {self.id}] Instantiated {len(self._organizations)} orgs from asset attributes.")
        return self._organizations

    def fetch_projects_via_relationship(self, params: Optional[Dict[str, Any]] = None) -> List[ProjectPydanticModel]:
        """Fetches Snyk projects related to this asset via the relationship link.

        This method uses the 'projects' relationship link provided in the asset data
        to paginate and fetch associated projects.

        Args:
            params: Optional query parameters to pass to the projects API endpoint.

        Returns:
            A list of ProjectPydanticModel instances.
        """
        self._logger.debug(f"[Asset ID: {self.id}] Fetching projects via relationship link...")
        from .project import ProjectPydanticModel # Local import
        _params = params if params is not None else {}
        
        if self._projects is not None:
            return self._projects


        if 'snyk' not in self.attributes.sources:
            self._logger.warning(f"Asset {self.id} does not have a Snyk source. Cannot fetch projects.")
            self._projects = []
            return self._projects

        projects_related_link: Optional[str] = None
        if self.relationships and self.relationships.projects and self.relationships.projects.links:
            projects_related_link = self.relationships.projects.links.related
        
        if not projects_related_link:
            self._logger.warning(f"[Asset ID: {self.id}] No 'related' link for projects in asset relationships.")
            self._projects = []
            return self._projects

        headers = {'Content-Type': 'application/json', 'Authorization': f'token {self._api_client.token}'}
        current_api_params = {'version': API_VERSION_ASSET, 'limit': 100}
        current_api_params.update(_params)
        
        all_project_data_items: List[Dict[str, Any]] = []
        try:
            for project_data_item in self._api_client.paginate(
                    endpoint=projects_related_link, params=current_api_params, data_key='data', headers=headers):
                all_project_data_items.append(project_data_item)
        except Exception as e_paginate:
            self._logger.error(f"[Asset ID: {self.id}] Error paginating projects: {e_paginate}", exc_info=True)
            self._projects = []
            return self._projects

        if not all_project_data_items:
            self._projects = []
            return self._projects

        org_context_list = self.organizations 

        project_futures = []
        for project_data in all_project_data_items:
            org_id_for_project = project_data.get('relationships', {}).get('organization', {}).get('data', {}).get('id')
            organization_object_for_project: Optional[OrganizationPydanticModel] = None
            if org_id_for_project and org_context_list:
                organization_object_for_project = next((org for org in org_context_list if org.id == org_id_for_project), None)
            
            future = self._api_client.submit_task(
                ProjectPydanticModel.from_api_response,
                project_data,
                self._api_client,
                organization_object_for_project,
                self._group
            )
            project_futures.append(future)

        projects_results: List[ProjectPydanticModel] = []
        for future in concurrent.futures.as_completed(project_futures):
            try:
                project_instance = future.result()
                if project_instance:
                    projects_results.append(project_instance)
            except Exception as e_future:
                self._logger.error(f"[Asset ID: {self.id}] Error instantiating project model: {e_future}", exc_info=True)
        
        self._projects = projects_results
        self._logger.info(f"[Asset ID: {self.id}] Fetched and instantiated {len(self._projects)} projects.")
        return self._projects

    def githubNameAndOwnerFromUrl(self) -> Optional[Tuple[str, str]]:
        """Extracts GitHub repository name and owner from the asset's browse_url.

        Returns:
            A tuple containing (repository_name, owner_name) if successful,
            otherwise None.
        """
        if not self.attributes.browse_url:
            self._logger.warning(f"No browser URL for asset {self.id}. Cannot extract GitHub Name/Owner.")
            return None
        try:
            parsed_url = urlparse(self.attributes.browse_url)
            if 'github.com' not in parsed_url.netloc.lower():
                self._logger.debug(f"Asset {self.id} browse_url not a GitHub URL: {self.attributes.browse_url}")
                return None
            path_segments = parsed_url.path.strip('/').split('/')
            if len(path_segments) >= 2:
                return path_segments[1], path_segments[0] # repo_name, owner_name
            return None
        except Exception as e:
            self._logger.error(f"Error parsing GitHub URL '{self.attributes.browse_url}': {e}", exc_info=True)
            return None

    def get_business_criticality_from_asset(self) -> Optional[str]:
        """Determines the business criticality based on the asset's rank.

        Returns:
            The business criticality string ('critical', 'high', 'medium', 'low')
            or None if rank is not available or invalid.
        """
        if not self.attributes.class_data or 'rank' not in self.attributes.class_data:
            self._logger.warning(f"Asset {self.id} has no class_data or rank.")
            return None
        try:
            rank = int(self.attributes.class_data['rank'])
            mapping = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
            return mapping.get(rank)
        except (ValueError, TypeError):
            self._logger.warning(f"Invalid rank '{self.attributes.class_data.get('rank')}' for asset {self.id}.")
            return None

    def get_lifecycle_from_asset(self) -> Optional[str]:
        """Retrieves the lifecycle stage of the asset from its app_context.

        Returns:
            The lifecycle stage ('production', 'development', 'sandbox') or
            defaults to 'Development' if incompatible, or None if not set.
        """
        lifecycle = self.attributes.app_lifecycle
        if lifecycle and lifecycle in ['production', 'development', 'sandbox']:
            return lifecycle
        elif lifecycle is None:
            self._logger.warning(f"No lifecycle for asset {self.id}.")
            return None
        else:
            self._logger.warning(f"Lifecycle '{lifecycle}' incompatible for asset {self.id}. Defaulting to 'Development'")
            return 'Development'
