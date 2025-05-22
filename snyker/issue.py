from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Tuple, Any
from .utils import datetime_converter
import logging
import json

if TYPE_CHECKING:
    from .api_client import APIClient
    from .organization import Organization
    from .asset import Asset
    from .project import Project
    from .group import Group

class Issue:
    """
    Represents a Snyk Issue, such as a vulnerability, license compliance problem,
    or code quality finding.

    This class encapsulates the data for an issue as returned by the Snyk API.
    It provides access to various attributes of the issue and includes nested
    classes to structure complex data like coordinates, severities, and risk factors.
    An Issue object is typically associated with a Project, Organization, or Group.

    Attributes:
        id (str): The unique identifier of the issue.
        type (str): The type of the issue (e.g., 'vuln', 'license').
        title (str): A human-readable title for the issue.
        effective_severity_level (str): The calculated severity of the issue.
        status (str): The current status of the issue (e.g., 'open', 'resolved').
        raw (Dict[str, Any]): The raw JSON data for the issue from the Snyk API.
        api_client (Optional[APIClient]): The API client for further calls.
        project (Optional[Project]): The Snyk Project this issue belongs to.
        org (Optional[Organization]): The Snyk Organization this issue belongs to.
        group (Optional[Group]): The Snyk Group this issue belongs to.
        logger (logging.Logger): Logger instance.
        coordinates (List[Issue.Coordinate]): Details on where the issue manifests.
        classes (List[Issue.Classes]): Classifications (e.g., CWEs).
        severities (List[Issue.Severities]): Detailed severity information.
        risk (Optional[Issue.Risk]): Risk assessment details.
    """
    def __init__(self,
                 issue_data: Dict[str, Any],
                 group: Optional['Group'] = None,
                 org: Optional['Organization'] = None,
                 project: Optional['Project'] = None,
                 ):
        """
        Initializes an Issue object.

        The issue must be contextualized by at least one of `group`, `org`, or `project`.
        The constructor parses `issue_data` to populate the issue's attributes and
        instantiates nested objects for structured data.

        Args:
            issue_data (Dict[str, Any]): Raw dictionary data for the issue from Snyk API.
            group (Optional['Group']): The parent Snyk Group.
            org (Optional['Organization']): The parent Snyk Organization.
            project (Optional['Project']): The parent Snyk Project.

        Raises:
            ValueError: If none of `group`, `org`, or `project` are provided.
            KeyError: If essential keys are missing from `issue_data`.
        """
        self.project: Optional['Project'] = None
        self.org: Optional['Organization'] = None
        self.group: Optional['Group'] = None
        self.api_client: Optional['APIClient'] = None
        
        _logger_source_name = "UnknownContext"
        if project and hasattr(project, 'logger') and project.logger:
            self.logger = project.logger
            _logger_source_name = f"Project:{project.id}"
        elif org and hasattr(org, 'logger') and org.logger:
            self.logger = org.logger
            _logger_source_name = f"Org:{org.id}"
        elif group and hasattr(group, 'logger') and group.logger:
            self.logger = group.logger
            _logger_source_name = f"Group:{group.id}"
        else:
            self.logger = logging.getLogger(f"{__name__}.IssueInstance")
            self.logger.warning("No logger provided by context; Issue created its own.")

        if group is None and org is None and project is None:
            raise ValueError("Issue must be created with Group, Organization, or Project context.")

        # Establish context hierarchy and API client
        if project is not None:
            self.project = project
            if hasattr(project, 'organization') and project.organization:
                self.org = project.organization
                if hasattr(self.org, 'group') and self.org.group:
                    self.group = self.org.group
            if hasattr(project, 'api_client') and project.api_client:
                 self.api_client = project.api_client
        elif org is not None:
            self.org = org
            if hasattr(org, 'group') and org.group:
                self.group = org.group
            if hasattr(org, 'api_client') and org.api_client:
                self.api_client = org.api_client
        elif group is not None:
            self.group = group
            if hasattr(group, 'api_client') and group.api_client:
                self.api_client = group.api_client
        
        # Fallback to group's API client if not set via more specific context
        if self.api_client is None and self.group and hasattr(self.group, 'api_client'):
            self.api_client = self.group.api_client
        
        if self.api_client is None:
            self.logger.warning(f"Issue {issue_data.get('id', 'UnknownID')} initialized without an APIClient.")


        self.raw = issue_data
        try:
            self.id = self.raw['id']
            self.type = self.raw['type']
            attributes = issue_data.get('attributes', {})
            self.created_at = datetime_converter(attributes['created_at'])
            self.updated_at = datetime_converter(attributes['updated_at'])
            self.title = attributes['title']
            self.effective_severity_level = attributes['effective_severity_level']
            self.ignored = bool(attributes.get('ignored', False))
            self.key = attributes.get('key')
            self.status = attributes['status']
        except KeyError as e:
            self.logger.error(f"KeyError initializing Issue: {e}. Raw data: {json.dumps(self.raw, indent=2)}")
            raise KeyError(f"Missing essential key in issue data: {e}") from e
            
        self.key_asset = attributes.get('key_asset')
        self.tool = attributes.get('tool')
        if self.status == 'resolved' and 'resolution' in attributes:
            self.resolved_at = datetime_converter(attributes['resolution']['resolved_at'])
            self.resolution_type = attributes['resolution']['type']
        
        # Parse nested structures
        self.coordinates: List[Issue.Coordinate] = []
        if 'coordinates' in attributes and isinstance(attributes['coordinates'], list):
             for coord_data in attributes['coordinates']:
                self.coordinates.append(self.Coordinate(coord_data, parent_logger=self.logger))

        self.classes: List[Issue.Classes] = []
        if 'classes' in attributes and isinstance(attributes['classes'], list):
            for class_data in attributes['classes']:
                self.classes.append(self.Classes(class_data, parent_logger=self.logger))
        
        self.risk: Optional[Issue.Risk] = None # Can be singular
        if 'risk' in attributes and isinstance(attributes['risk'], dict):
            self.risk = self.Risk(attributes['risk'], parent_logger=self.logger)
        
        self.severities: List[Issue.Severities] = []
        if 'severities' in attributes and isinstance(attributes['severities'], list):
            for severity_data in attributes['severities']:
                self.severities.append(self.Severities(severity_data, parent_logger=self.logger))
        
        # Parse relationships
        relationships = issue_data.get('relationships', {})
        if 'organization' in relationships:
            self.org_id = relationships['organization'].get('data', {}).get('id')
        if 'scan_item' in relationships:
            scan_item_data = relationships['scan_item'].get('data', {})
            if scan_item_data.get('type') == 'project':
                self.project_id = scan_item_data.get('id')
            elif scan_item_data.get('type') == 'environment':
                self.environment_id = scan_item_data.get('id')
        if 'ignore' in relationships:
            self.ignore_id = relationships['ignore'].get('data', {}).get('id')
        
        self.logger.debug(f"[{_logger_source_name}] Issue {self.id} ('{self.title}') initialized.")

    def get_project(self) -> Optional['Project']:
        """
        Lazily fetches and returns the full Project object associated with this issue.

        This method attempts to retrieve the project if `self.project_id` and
        `self.org` (Organization context) are available. The fetched Project
        object is cached in `self.project`.

        Returns:
            Optional['Project']: The associated Project object, or None if it cannot be fetched.
        """
        if self.project: 
            return self.project
        
        if hasattr(self, 'project_id') and self.project_id and self.org:
            self.logger.debug(f"[Issue ID: {self.id}] Attempting to fetch Project object for project_id: {self.project_id}")
            try:
                project_obj = self.org.get_project(project_id=self.project_id)
                if project_obj:
                    self.project = project_obj
                    return self.project
                else:
                    self.logger.warning(f"[Issue ID: {self.id}] Failed to fetch Project object for project_id: {self.project_id} from org {self.org.id}")
            except Exception as e:
                self.logger.error(f"[Issue ID: {self.id}] Error fetching Project object for project_id: {self.project_id}: {e}", exc_info=True)
        elif not hasattr(self, 'project_id') or not self.project_id:
            self.logger.debug(f"[Issue ID: {self.id}] No project_id available to fetch Project object.")
        elif not self.org:
            self.logger.debug(f"[Issue ID: {self.id}] No organization context (self.org) available to fetch Project object.")
            
        return None

    class Coordinate:
        """
        Represents the coordinates of an issue, detailing where it manifests.
        This could include file paths, dependency information, or specific code locations.

        Attributes:
            representations (List[Issue.Coordinate.Representation]): Specific manifestations.
            remedies (List[Dict[str, Any]]): Suggested remedies or fixes.
            is_fixable_manually (bool): If the issue can be fixed manually.
            is_fixable_snyk (bool): If Snyk can provide an automated fix.
            reachability (Optional[str]): Information about the issue's reachability.
        """
        def __init__(self, coordinate_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
            self.logger = parent_logger or logging.getLogger(f"{__name__}.Coordinate")
            self.raw_coordinate_data = coordinate_data

            self.representations: List[Issue.Coordinate.Representation] = []
            if 'representations' in coordinate_data and isinstance(coordinate_data['representations'], list):
                for rep_data in coordinate_data['representations']:
                    self.representations.append(self.Representation(rep_data, parent_logger=self.logger))
            
            self.remedies: List[Dict[str, Any]] = coordinate_data.get('remedies', [])
            
            self.is_fixable_manually = bool(coordinate_data.get('is_fixable_manually'))
            self.is_fixable_snyk = bool(coordinate_data.get('is_fixable_snyk'))
            self.is_fixable_upstream = bool(coordinate_data.get('is_fixable_upstream'))
            self.is_patchable = bool(coordinate_data.get('is_patchable'))
            self.is_pinnable = bool(coordinate_data.get('is_pinnable'))
            self.is_upgradeable = bool(coordinate_data.get('is_upgradeable'))
            self.reachability = coordinate_data.get('reachability')
            
        class Representation:
            """
            A specific representation or instance of an issue's coordinate.
            For example, a vulnerability might have multiple representations if it
            appears in different files or through different dependency paths.

            Attributes:
                resource_path (Optional[str]): Path to the affected resource.
                package_name (Optional[str]): Name of the affected package.
                package_version (Optional[str]): Version of the affected package.
                source_location (Optional[Dict[str, Any]]): Raw source location data.
                commit_id (Optional[str]): Commit ID if applicable.
                file (Optional[str]): File path.
                start_line (Optional[int]): Start line number.
                # ... and other location details ...
            """
            def __init__(self, rep_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
                self.logger = parent_logger or logging.getLogger(f"{__name__}.Representation")
                self.raw_rep_data = rep_data

                self.resource_path = rep_data.get('resourcePath')
                dependency_info = rep_data.get('dependency', {})
                self.package_name = dependency_info.get('package_name')
                self.package_version = dependency_info.get('package_version')
                
                self.source_location = rep_data.get('sourceLocation')
                if isinstance(self.source_location, dict):
                    self.commit_id = self.source_location.get('commit_id')
                    self.file = self.source_location.get('file')
                    region = self.source_location.get('region', {})
                    if isinstance(region, dict):
                        start_info = region.get('start', {})
                        end_info = region.get('end', {})
                        self.start_line = start_info.get('line') if isinstance(start_info, dict) else None
                        self.start_column = start_info.get('column') if isinstance(start_info, dict) else None
                        self.end_line = end_info.get('line') if isinstance(end_info, dict) else None
                        self.end_column = end_info.get('column') if isinstance(end_info, dict) else None
                    else:
                        self.start_line = self.start_column = self.end_line = self.end_column = None
                else:
                    self.commit_id = self.file = None
                    self.start_line = self.start_column = self.end_line = self.end_column = None


    class Problems:
        """
        Details about the underlying problem or vulnerability associated with an issue.
        Often contains identifiers like CVE, CWE, or Snyk vulnerability ID.

        Attributes:
            id (str): The identifier of the problem (e.g., CVE-2021-12345).
            type (str): The type of problem identifier (e.g., 'cve', 'snyk').
            source (str): The source of the problem data (e.g., 'NVD', 'Snyk').
            updated_at (datetime): When this problem information was last updated.
            disclosed_at (Optional[datetime]): When the problem was publicly disclosed.
            discovered_at (Optional[datetime]): When Snyk discovered this problem.
            url (Optional[str]): A URL for more information about the problem.
        """
        def __init__(self, problem_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
            self.logger = parent_logger or logging.getLogger(f"{__name__}.Problems")
            self.raw_problem_data = problem_data

            self.id = problem_data['id']
            self.type = problem_data.get('type')
            self.source = problem_data['source']
            
            if 'updated_at' in problem_data:
                 self.updated_at = datetime_converter(problem_data['updated_at'])
            else:
                self.updated_at = None
                self.logger.warning("Problem data missing 'updated_at'")

            if 'disclosed_at' in problem_data:
                self.disclosed_at = datetime_converter(problem_data['disclosed_at'])
            else:
                self.disclosed_at = None
            if 'discovered_at' in problem_data:
                self.discovered_at = datetime_converter(problem_data['discovered_at'])
            else:
                self.discovered_at = None
            self.url = problem_data.get('url')

    class Severities:
        """
        Represents a single severity assessment for an issue.
        An issue might have multiple severity scores from different sources or versions.

        Attributes:
            level (str): The severity level (e.g., 'high', 'medium', 'low').
            modification_time (datetime): Timestamp of when this severity was set/modified.
            score (Optional[float]): Numerical score (e.g., CVSS score).
            source (str): The source of this severity assessment (e.g., 'Snyk', 'NVD').
            vector (Optional[str]): The CVSS vector string, if applicable.
            version (Optional[str]): The version of the scoring system (e.g., 'CVSS:3.1').
        """
        def __init__(self, severity_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
            self.logger = parent_logger or logging.getLogger(f"{__name__}.Severities")
            self.raw_severity_data = severity_data

            self.level = severity_data.get('level')
            if 'modification_time' in severity_data:
                self.modification_time = datetime_converter(severity_data['modification_time'])
            else:
                self.modification_time = None
                self.logger.warning("Severity data missing 'modification_time'")
            self.score = severity_data.get('score')
            self.source = severity_data.get('source')
            self.vector = severity_data.get('vector')
            self.version = severity_data.get('version')
            
    class Classes:
        """
        Represents a classification for an issue, such as a CWE (Common Weakness Enumeration).

        Attributes:
            id (str): The identifier of the classification (e.g., 'CWE-79').
            source (str): The source of the classification (e.g., 'CWE').
            type (str): The type of classification.
            url (Optional[str]): A URL for more information about this classification.
        """
        def __init__(self, classes_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
            self.logger = parent_logger or logging.getLogger(f"{__name__}.Classes")
            self.raw_classes_data = classes_data

            self.id = classes_data.get('id')
            self.source = classes_data.get('source')
            self.type = classes_data.get('type')
            self.url = classes_data.get('url')

    class Risk:
        """
        Encapsulates risk assessment details for an issue, including factors and overall score.

        Attributes:
            factors (List[Issue.Risk.Factor]): A list of individual risk factors.
            score (Optional[float]): The calculated risk score.
            model (Optional[str]): The model used for risk calculation.
        """
        def __init__(self, risk_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
            self.logger = parent_logger or logging.getLogger(f"{__name__}.Risk")
            self.raw_risk_data = risk_data

            self.factors: List[Issue.Risk.Factor] = []
            if 'factors' in risk_data and isinstance(risk_data['factors'], list):
                for factor_data in risk_data['factors']:
                    self.factors.append(self.Factor(factor_data, parent_logger=self.logger))
            
            score_data = risk_data.get('score', {})
            if isinstance(score_data, dict):
                self.score = score_data.get('value')
                self.model = score_data.get('model')
            else:
                self.score = None
                self.model = None

        class Factor:
            """
            Represents an individual factor contributing to an issue's risk assessment.

            Attributes:
                name (str): Name of the risk factor (e.g., 'hasFix', 'exploitMaturity').
                value (bool): The boolean value of this factor.
                updated_at (datetime): When this factor was last updated.
                included_in_score (bool): Whether this factor was included in the score.
                links (List[str]): URLs or references related to this factor's evidence.
            """
            def __init__(self, factor_data: Dict[str, Any], parent_logger: Optional[logging.Logger] = None):
                self.logger = parent_logger or logging.getLogger(f"{__name__}.Factor")
                self.raw_factor_data = factor_data

                self.included_in_score = bool(factor_data.get('included_in_score', False))
                self.name = factor_data.get('name')
                if 'updated_at' in factor_data:
                    self.updated_at = datetime_converter(factor_data['updated_at'])
                else:
                    self.updated_at = None
                    self.logger.warning(f"Risk factor data missing 'updated_at' for factor '{self.name}'")
                self.value = bool(factor_data.get('value'))
                
                self.links: List[str] = []
                evidence = factor_data.get('evidence')
                if evidence:
                    if isinstance(evidence, str):
                        self.links.append(evidence)
                    elif isinstance(evidence, dict) and 'href' in evidence:
                        self.links.append(evidence['href'])
                    elif isinstance(evidence, list):
                        for link_item in evidence:
                            if isinstance(link_item, str):
                                self.links.append(link_item)
                            elif isinstance(link_item, dict) and 'href' in link_item:
                                self.links.append(link_item['href'])
