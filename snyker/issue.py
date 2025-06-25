from __future__ import annotations
from typing import List, Dict, Optional, Any, TYPE_CHECKING
import logging
import json # For potential debugging, though Pydantic handles serialization

from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

from snyker.utils import datetime_converter
from snyker.config import API_CONFIG
from .api_client import APIClient
# from .organization import OrganizationPydanticModel # Circular import
from .project import ProjectPydanticModel
# from .group import GroupPydanticModel # Moved to TYPE_CHECKING

if TYPE_CHECKING:
    from .organization import OrganizationPydanticModel
    from .group import GroupPydanticModel


class IssueCoordinateRepresentation(BaseModel):
    """Represents one way an issue is identified at a specific location.
    
    This can include package information, file paths, or commit details.
    """
    resource_path: Optional[str] = Field(default=None, alias="resourcePath")
    package_name: Optional[str] = Field(default=None, alias="packageName")
    package_version: Optional[str] = Field(default=None, alias="packageVersion")
    commit_id: Optional[str] = None
    file: Optional[str] = None
    start_line: Optional[int] = None
    start_column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    @model_validator(mode='before')
    @classmethod
    def extract_nested_fields(cls, data: Any) -> Any:
        """Flattens nested 'dependency' and 'sourceLocation' fields from API response."""
        if isinstance(data, dict):
            dependency_info = data.pop('dependency', {})
            if dependency_info:
                data['packageName'] = dependency_info.get('package_name')
                data['packageVersion'] = dependency_info.get('package_version')
            
            source_location = data.pop('sourceLocation', {})
            if isinstance(source_location, dict):
                data['commit_id'] = source_location.get('commit_id')
                data['file'] = source_location.get('file')
                region = source_location.get('region', {})
                if isinstance(region, dict):
                    start_info = region.get('start', {})
                    end_info = region.get('end', {})
                    data['start_line'] = start_info.get('line') if isinstance(start_info, dict) else None
                    data['start_column'] = start_info.get('column') if isinstance(start_info, dict) else None
                    data['end_line'] = end_info.get('line') if isinstance(end_info, dict) else None
                    data['end_column'] = end_info.get('column') if isinstance(end_info, dict) else None
        return data

class IssueCoordinate(BaseModel):
    """Defines the location and fixability of an issue."""
    representations: List[IssueCoordinateRepresentation] = Field(default_factory=list)
    remedies: List[Dict[str, Any]] = Field(default_factory=list)
    is_fixable_manually: bool = Field(default=False, alias="isFixableManually")
    is_fixable_snyk: bool = Field(default=False, alias="isFixableSnyk")
    is_fixable_upstream: Optional[bool] = Field(default=None, alias="isFixableUpstream")
    is_patchable: Optional[bool] = Field(default=None, alias="isPatchable")
    is_pinnable: Optional[bool] = Field(default=None, alias="isPinnable")
    is_upgradeable: Optional[bool] = Field(default=None, alias="isUpgradeable")
    reachability: Optional[str] = None

class IssueProblem(BaseModel):
    """Details about a specific problem associated with an issue (e.g., a CWE)."""
    id: str
    type: Optional[str] = None
    source: Optional[str] = None
    updated_at: Optional[Any] = Field(default=None) 
    disclosed_at: Optional[Any] = Field(default=None)
    discovered_at: Optional[Any] = Field(default=None)
    url: Optional[str] = None

    @field_validator('updated_at', 'disclosed_at', 'discovered_at', mode='before')
    @classmethod
    def convert_datetimes(cls, value: Any) -> Optional[Any]:
        """Converts string datetime fields to datetime objects."""
        if value:
            return datetime_converter(value)
        return None

class IssueSeverity(BaseModel):
    """Severity information for an issue."""
    level: Optional[str] = None
    modification_time: Optional[Any] = Field(default=None)
    score: Optional[float] = None
    source: Optional[str] = None
    vector: Optional[str] = None
    version: Optional[str] = None

    @field_validator('modification_time', mode='before')
    @classmethod
    def convert_mod_time(cls, value: Any) -> Optional[Any]:
        """Converts modification_time to a datetime object."""
        if value:
            return datetime_converter(value)
        return None

class IssueClass(BaseModel):
    """Classification of an issue (e.g., CWE)."""
    id: Optional[str] = None
    source: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None

class IssueRiskFactor(BaseModel):
    """A specific risk factor contributing to an issue's overall risk."""
    name: Optional[str] = None
    value: Optional[bool] = None
    updated_at: Optional[Any] = Field(default=None, alias="updatedAt")
    included_in_score: bool = Field(default=False, alias="includedInScore")
    links: List[str] = Field(default_factory=list)

    @field_validator('updated_at', mode='before')
    @classmethod
    def convert_update_time(cls, value: Any) -> Optional[Any]:
        """Converts updated_at to a datetime object."""
        if value:
            return datetime_converter(value)
        return None
        
    @model_validator(mode='before')
    @classmethod
    def extract_links(cls, data: Any) -> Any:
        """Extracts links from 'evidence' field if present."""
        if isinstance(data, dict):
            evidence = data.pop('evidence', None)
            links_list = []
            if evidence:
                if isinstance(evidence, str):
                    links_list.append(evidence)
                elif isinstance(evidence, dict) and 'href' in evidence:
                    links_list.append(evidence['href'])
                elif isinstance(evidence, list):
                    for link_item in evidence:
                        if isinstance(link_item, str):
                            links_list.append(link_item)
                        elif isinstance(link_item, dict) and 'href' in link_item:
                            links_list.append(link_item['href'])
            if links_list:
                 data['links'] = links_list
        return data


class IssueRisk(BaseModel):
    """Overall risk assessment for an issue."""
    factors: List[IssueRiskFactor] = Field(default_factory=list)
    score: Optional[float] = None
    model: Optional[str] = None

    @model_validator(mode='before')
    @classmethod
    def extract_score_model(cls, data: Any) -> Any:
        """Extracts 'score' and 'model' from a nested score object."""
        if isinstance(data, dict):
            score_data = data.pop('score', {})
            if isinstance(score_data, dict):
                data['score'] = score_data.get('value')
                data['model'] = score_data.get('model')
        return data

class IssueAttributes(BaseModel):
    """Core attributes of a Snyk issue."""
    created_at: Optional[Any] = Field(default=None)
    updated_at: Optional[Any] = Field(default=None)
    title: str 
    effective_severity_level: Optional[str] = Field(default=None)
    ignored: bool = Field(default=False)
    key: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None # Added field for issue type (e.g., "license", "vuln", "iac")
    key_asset: Optional[str] = Field(default=None)
    tool: Optional[str] = None
    
    resolved_at: Optional[Any] = Field(default=None)
    resolution_type: Optional[str] = Field(default=None)

    coordinates: List[IssueCoordinate] = Field(default_factory=list)
    classes: List[IssueClass] = Field(default_factory=list)
    risk: Optional[IssueRisk] = None
    severities: List[IssueSeverity] = Field(default_factory=list)
    problems: List[IssueProblem] = Field(default_factory=list)

    @field_validator('created_at', 'updated_at', 'resolved_at', mode='before')
    @classmethod
    def convert_datetimes(cls, value: Any) -> Optional[Any]:
        """Converts string datetime fields to datetime objects."""
        if value:
            return datetime_converter(value)
        return None

    @model_validator(mode='before')
    @classmethod
    def extract_resolution(cls, data: Any) -> Any:
        """Extracts resolution fields from a nested 'resolution' object."""
        if isinstance(data, dict):
            resolution_data = data.pop('resolution', {})
            if isinstance(resolution_data, dict):
                data['resolvedAt'] = resolution_data.get('resolved_at')
                data['resolutionType'] = resolution_data.get('type')
        return data

class RelationshipData(BaseModel):
    """Generic model for relationship data (ID and type)."""
    id: Optional[str] = None
    type: Optional[str] = None

class IssueRelationships(BaseModel):
    """Relationships of a Snyk issue to other entities."""
    organization: Optional[RelationshipData] = None
    scan_item: Optional[RelationshipData] = Field(default=None)
    ignore: Optional[RelationshipData] = None

class IssuePydanticModel(BaseModel):
    """Represents a Snyk issue.

    Attributes:
        id: The unique identifier of the issue.
        type: The type of the Snyk entity (should be "issue").
        attributes: Detailed attributes of the issue.
        relationships: Relationships to other Snyk entities like organization or scan_item.
    """
    id: str
    type: str
    attributes: IssueAttributes
    relationships: Optional[IssueRelationships] = None

    _api_client: APIClient = PrivateAttr()
    _organization: Optional[OrganizationPydanticModel] = PrivateAttr(default=None)
    _project: Optional[ProjectPydanticModel] = PrivateAttr(default=None)
    _group: Optional[GroupPydanticModel] = PrivateAttr(default=None)
    _logger: logging.Logger = PrivateAttr()

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_api_response(cls,
                          issue_data: Dict[str, Any],
                          api_client: APIClient,
                          organization: Optional[OrganizationPydanticModel] = None,
                          project: Optional[ProjectPydanticModel] = None,
                          group: Optional[GroupPydanticModel] = None
                          ) -> IssuePydanticModel:
        """Creates an IssuePydanticModel instance from API response data.

        Args:
            issue_data: The 'data' part of an API item representing an issue.
            api_client: An instance of the APIClient.
            organization: The parent OrganizationPydanticModel instance, if applicable.
            project: The parent ProjectPydanticModel instance, if applicable.
            group: The parent GroupPydanticModel instance, if applicable.

        Returns:
            An instance of IssuePydanticModel.
        """
        instance = cls(**issue_data)
        instance._api_client = api_client
        instance._organization = organization
        instance._project = project
        instance._group = group
        instance._logger = api_client.logger

        instance._logger.debug(f"[Issue ID: {instance.id}] Created issue object for '{instance.title}'")
        
        if API_CONFIG.get("loading_strategy") == "eager" and not instance._project:
            instance._fetch_project_if_needed()

        return instance

    @property
    def title(self) -> str:
        """The title of the issue."""
        return self.attributes.title

    @property
    def effective_severity_level(self) -> Optional[str]:
        """The effective severity level of the issue (e.g., 'high', 'medium')."""
        return self.attributes.effective_severity_level

    @property
    def status(self) -> Optional[str]:
        """The current status of the issue (e.g., 'open', 'resolved')."""
        return self.attributes.status
        
    @property
    def project(self) -> Optional[ProjectPydanticModel]:
        """The Snyk project associated with this issue.
        
        Fetched lazily or eagerly based on SDK configuration.
        """
        if self._project is None:
            if API_CONFIG.get("loading_strategy") == "lazy":
                self._fetch_project_if_needed()
        return self._project

    def _fetch_project_if_needed(self) -> None:
        """Internal method to fetch the related project if not already loaded.
        
        This is typically called by the `project` property during lazy loading.
        """
        if self._project:
            return

        # Local imports to resolve names at runtime
        from .organization import OrganizationPydanticModel
        from .group import GroupPydanticModel

        project_id: Optional[str] = None
        org_for_project_fetch: Optional[OrganizationPydanticModel] = self._organization

        if self.relationships and self.relationships.scan_item and \
           self.relationships.scan_item.type == 'project':
            project_id = self.relationships.scan_item.id
        
        if not org_for_project_fetch and self.relationships and self.relationships.organization:
            org_id_from_rel = self.relationships.organization.id if self.relationships.organization else None
            if org_id_from_rel:
                self._logger.debug(f"[Issue ID: {self.id}] Attempting to get Organization context (ID: {org_id_from_rel}) for project fetch.")
                if self._group:
                    org_for_project_fetch = self._group.get_organization_by_id(org_id_from_rel)
            else:
                self._logger.debug(f"[Issue ID: {self.id}] No organization ID in relationships to fetch Organization context.")


        if project_id and org_for_project_fetch:
            self._logger.debug(f"[Issue ID: {self.id}] Lazily fetching Project (ID: {project_id}) via Org (ID: {org_for_project_fetch.id}).")
            try:
                project_model = org_for_project_fetch.get_specific_project(project_id=project_id)
                if project_model:
                    self._project = project_model
                else:
                    self._logger.warning(f"[Issue ID: {self.id}] Failed to fetch Project (ID: {project_id}). Project model was None.")
            except Exception as e:
                self._logger.error(f"[Issue ID: {self.id}] Error fetching Project (ID: {project_id}): {e}", exc_info=True)
        elif not project_id:
             self._logger.warning(
                 f"[Issue ID: {self.id}] No project_id in relationships to fetch Project. "
                 f"Relationships data: {self.relationships.model_dump_json(indent=2) if self.relationships else 'None'}"
            )
        elif not org_for_project_fetch:
             self._logger.warning(f"[Issue ID: {self.id}] No Organization context to fetch Project (ID: {project_id}).")
