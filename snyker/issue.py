from utils import get_nested_value # Helper function to safely retrieve nested values
import types

class Issue:
    def __init__(self, issue_data: dict, group=None, org=None, project=None, api_client=None):
        self.group = group
        self.org = org
        self.project = project
        self.api_client = api_client
        self.raw = issue_data
        self.id = get_nested_value(issue_data, ['id'], None)
        self.effectiveSeverityLevel = get_nested_value(issue_data, ['attributes', 'effective_severity_level'], None)
        self.createdAt = get_nested_value(issue_data, ['attributes', 'created_at'], None)
        self.updatedAt = get_nested_value(issue_data, ['attributes', 'updated_at'], None)
        self.title = get_nested_value(issue_data, ['attributes', 'title'], None)
        self.type = get_nested_value(issue_data, ['attributes', 'type'], None)
        self.ignored = get_nested_value(issue_data, ['attributes', 'ignored'], None)
        self.risk = Risk(get_nested_value(issue_data, ['attributes', 'risk'], {}))
        self.coordinates = get_nested_value(issue_data, ['attributes', 'coordinates'], [])
        self.status = get_nested_value(issue_data, ['attributes', 'status'], None)
        # Getting product-specific attributes
        if self.type == 'code':
            for coordinate in self.coordinates:
                for representation in coordinate['representations'] if 'representations' in coordinate else []:
                    commitId = get_nested_value(representation, ['sourceLocation','commit_id'], None)
                    file = get_nested_value(representation, ['sourceLocation','file_path'], None)
                    region = get_nested_value(representation, ['sourceLocation','region'], None)
                    self.sourceLocation = {'commitId': commitId, 'file': file, 'region': region}
                break
        elif self.type == 'package_vulnerability':
            self.packages = []
            for coordinate in self.coordinates if self.type == 'package_vulnerability' else []:
                for representation in coordinate['representations'] if 'representations' in coordinate else []:
                    packageVersion = get_nested_value(representation, ['dependency','package_name'], None)
                    packageName = get_nested_value(representation, ['dependency','package_version'], None)
                    self.packages.append({'packageName': packageName, 'packageVersion': packageVersion})




class Risk:
    def __init__(self, risk_data: dict):
        self.score = get_nested_value(risk_data, ['score', 'value'], None)
        self.model = get_nested_value(risk_data, ['score', 'model'], None)