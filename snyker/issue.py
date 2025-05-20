from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Tuple
from snyker import get_nested, datetime_converter
from typing import TYPE_CHECKING, List, Dict, Optional

if TYPE_CHECKING:
    from snyker import APIClient, Organization, Asset, Project, Issue


class Issue:
    def __init__(self,
                 issue_data: dict,
                 group: Optional['Group'] = None,
                 org: Optional['Organization'] = None,
                 project: Optional['Project'] = None,
                 ):

        # Issue must be created with one of the following attached to it: Group, Organization, Project
        if group is None and org is None and project is None:
            raise ValueError("Issue must be created with one of the following: Group, Organization, Project")
        if project is not None:
            self.project = project
            self.group = project.group
            self.org = project.org
        elif org is not None:
            self.org = org
            self.group = org.group
        self.raw = issue_data
        self.id = self.raw['id']
        self.type = self.raw['type']  # package_vulnerability, license, code, custom, config

        # Attributes
        attributes = issue_data['attributes']
        self.created_at = datetime_converter(attributes['created_at'])
        self.updated_at = datetime_converter(attributes['updated_at'])
        self.title = attributes['title']
        self.effective_severity_level = attributes['effective_severity_level']  # info, low, medium, high, critical
        self.ignored = bool(attributes['ignored'])
        self.key = attributes['key']  # Project-scoped identities
        self.status = attributes['status']  # open, resolved
        # Optional attributes
        if attributes.get('key_asset'):
            self.key_asset = attributes['key_asset']  # Asset-scoped identities
        if attributes.get('tool'):
            self.tool = attributes.get('tool')  # Tool that generated the issue
        if self.status == 'resolved':
            self.resolved_at = datetime_converter(attributes['resolution']['resolved_at'])
            self.resolution_type = attributes['resolution']['type']
        self.coordinates = get_nested(issue_data, ['attributes', 'coordinates'], [])
        self.status = get_nested(issue_data, ['attributes', 'status'], None)
        # Classes
        self.classes = []
        for class_data in attributes['classes']:
            self.classes.append(self.Classes(class_data))
        # Coordinates
        self.coordinates = []
        if 'coordinates' in attributes:
            for coordinate_data in attributes['coordinates']:
                self.coordinates.append(coordinate_data)
        # Risk
        self.risk = []
        if 'risk' in attributes:
            self.risk.append(self.Risk(attributes['risk']))
        # Severities
        if 'severities' in attributes:
            self.severities = []
            for severity_data in attributes['severities']:
                self.severities.append(self.Severities(severity_data))
        # Relationships
        if 'organization' in issue_data['relationships']:
            self.org_id = issue_data['relationships']['organization']['data']['id']
            self.org_uri = issue_data['relationships']['organization']['links']['related']
        if 'scan_item' in issue_data['relationships']:
            self.project_id = issue_data['relationships']['scan_item']['data']['id']
            self.project_uri = issue_data['relationships']['scan_item']['links']['related']

    class Coordinate:
        """
        Coordinate class represents the coordinates of the issue.
        """
        def __init__(self, coordinate_data: dict):
            self.representations = []
            if 'representations' in coordinate_data:
                for representation_data in coordinate_data['representations']:
                    self.representations.append(self.Representation(representation_data))   
            if 'remedies' in coordinate_data:  
                for remedy in coordinate_data['remedies']:
                    self.remedies.append(remedy)
            self.is_fixable_manually = bool(coordinate_data.get('is_fixable_manually'))
            self.is_fixable_snyk = bool(coordinate_data.get('is_fixable_snyk'))
            self.is_fixable_upstream = bool(coordinate_data.get('is_fixable_upstream'))
            self.is_patchable = bool(coordinate_data.get('is_patchable'))
            self.is_pinnable = bool(coordinate_data.get('is_pinnable'))
            self.is_upgradeable = bool(coordinate_data.get('is_upgradeable'))
            self.reachability = coordinate_data.get('reachability')
            

        class Representation:
            """
            Representation class represents the representation of the issue.
            """
            def __init__(self, rep: dict):
                if 'resourcePath' in rep:
                    self.resource_path = rep['resourcePath']
                if 'dependency' in rep:
                    self.package_name = rep['dependency']['package_name']
                    self.package_version = rep['dependency']['package_version']
                if 'sourceLocation' in rep:
                    self.source_location = rep['sourceLocation']
                    self.commit_id = rep['sourceLocation'].get('commit_id')
                    self.file = rep['sourceLocation'].get('file')
                    self.start_line = rep['sourceLocation'].get('region')['start'].get('line')
                    self.start_column = rep['sourceLocation'].get('region')['start'].get('column')
                    self.end_line = rep['sourceLocation'].get('region')['end'].get('line')
                    self.end_column = rep['sourceLocation'].get('region')['end'].get('column')
    class Problems:
        """
        Problems class represents the problems of the issue.
        """
        def __init__(self, problem_data: dict):
            self.id = problem_data['id']
            self.type = problem_data['type']
            self.source = problem_data['source']
            self.updated_at = datetime_converter(problem_data['updated_at'])
            if 'disclosed_at' in problem_data:
                self.disclosed_at = datetime_converter(problem_data['disclosed_at'])
            if 'discovered_at' in problem_data:
                self.discovered_at = datetime_converter(problem_data['discovered_at'])
            if 'updated_at' in problem_data:
                self.updated_at = datetime_converter(problem_data['updated_at'])
            if 'url' in problem_data:
                self.url = problem_data['url']

    class Severities:
        """
        Severities class represents the severity levels of the issue.
        """
        def __init__(self, severity_data: dict):
            self.level = severity_data['level']
            self.modification_time = datetime_converter(severity_data['modification_time'])
            self.score = severity_data['score']
            self.source = severity_data['source']
            self.vector = severity_data['vector']
            self.version = severity_data['version']
            
    class Classes:
        """
        Classes class represents the classification of the issue. Example: CWE, CVE
        """
        def __init__(self, classes_data: dict):
            self.id = classes_data['id']
            self.source = classes_data['source']
            self.type = classes_data['type']
            self.url = classes_data.get('url', None)  # Optional in API spec

    class Risk:
        """
        Risk class represents the risk score of the issue, the model for calculation between 0-1000
        as well as the factors that contribute to it.
        """
        def __init__(self, risk_data: dict):
            self.factors = []
            for factor_data in risk_data['factors']:
                self.factors.append(self.Factor(factor_data))
            if risk_data.get('score'):
                self.score = risk_data['score']['value']
                self.model = risk_data['score']['model']

        class Factors:
            """
            Factors class represents the factors of the risk score.
            """
            def __init__(self, factor_data: dict):
                self.included_in_score = bool(factor_data['included_in_score'])
                self.name = factor_data['name']
                self.updated_at = datetime_converter(factor_data['updated_at'])
                self.value = bool(factor_data['value'])
                self.links = []
                if 'links' in factor_data:
                    if isinstance(factor_data['evidence'], str):
                        self.links.append(factor_data['evidence'])
                    elif isinstance(factor_data['evidence'], dict):
                        self.links.append(factor_data['evidence']['href'])
