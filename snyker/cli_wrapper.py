from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional
if TYPE_CHECKING:
    from snyker import Asset

from snyker import Group
import os
import subprocess
import traceback
import json


class CLIWrapper:
    def __init__(self,
                 group: Optional['Group'] = None,
                 project_directory_override: Optional[str] = None):
        self.org_id = None
        self.group = Group()
        self.api_client = self.group.api_client
        self.logger = self.api_client.logger
        self.assets = None
        self.project_directory = None  # Initialize to None

        if project_directory_override:
            self.project_directory = project_directory_override
            self.logger.info(f"[CLI].__init__: Using explicitly provided project directory: {self.project_directory}")
        else:
            known_ci_vars = [
                ('GITHUB_WORKSPACE', 'GitHub Actions'),
                ('CI_PROJECT_DIR', 'GitLab CI'),
                ('BITBUCKET_CLONE_DIR', 'Bitbucket Pipelines'),
                ('CIRCLE_WORKING_DIRECTORY', 'CircleCI'),
                ('WORKSPACE', 'Jenkins / Generic'),
                ('BUILD_SOURCESDIRECTORY', 'Azure DevOps'),
            ]
            detected_ci_env = "Unknown"

            for var_name, ci_name in known_ci_vars:
                path = os.getenv(var_name)
                if path:
                    self.project_directory = path
                    detected_ci_env = ci_name
                    self.logger.info(
                        f"[CLI].__init__: Detected {detected_ci_env} environment. "
                        f"Using project directory: {self.project_directory} (from ${var_name})"
                    )
                    break
            
            if not self.project_directory:
                checked_vars_str = ", ".join([f"${var}" for var, _ in known_ci_vars])
                self.logger.warning(
                    "[CLI].__init__: Could not automatically determine project directory from known CI/CD "
                    f"environment variables. Checked: {checked_vars_str}. "
                    "Current directory will be used if not explicitly changed by change_directory()."
                )

    def change_directory(self, directory: Optional[str] = None):
        """
        Changes the current working directory to the git directory if set.
        :return:
        """
        if directory:
            os.chdir(directory)
            self.logger.info(f"[CLI].change_directory: {directory}")
        elif self.project_directory is not None:
            os.chdir(self.project_directory)
            self.logger.info(f"[CLI].change_directory to: {self.project_directory}")
        else:
            self.logger.warning(
                "[CLI].change_directory: No project directory was automatically detected or explicitly set, "
                "and no directory argument was provided. Current directory remains unchanged."
            )

    def flight_check(self, minimum_version=None):
        """
        Check if Snyk CLI is installed and its version
        :param minimum_version:
        :return:
        """
        try:
            result = subprocess.run(['snyk', '-v'], capture_output=True, text=True)
            if result.returncode == 127:
                self.logger.error("[CLI].flight_check: Snyk CLI not found. Please install Snyk CLI.")
                exit(1)
            if result.returncode != 0:
                self.logger.error(f"[CLI].flight_check: Error running Snyk CLI: {result.stderr}")
                exit(1)
            version = result.stdout.strip()
            self.logger.info(f"[CLI].flight_check: using version {version}")
            if minimum_version and version < minimum_version:
                self.logger.error(f"[CLI].flight_check:Snyk CLI version {version} is not supported."
                                  f"Please update to {minimum_version} or greater.")
                exit(1)
        except Exception as e:
            self.logger.error(f"[CLI].flight_check: Error in flight_check: {e}")
            traceback.print_exc()
            exit(1)

    def run(self, params: dict = {}, param_str: Optional[str] = None) -> subprocess.CompletedProcess:
        """
        Runs Snyk CLI in a subprocess and returns the CompletedProcess object
        :return: subprocess.CompletedProcess
        """
        try:
            if param_str:
                command = param_str.split(' ')
            else:
                command = ['snyk']
                for key, value in params.items():
                    if value == ('' or None): # Handles cases like {'--all-projects': None} or {'--all-projects': ''}
                        command.append(f'{key}')
                    else:
                        command.append(f'{key}={value}')
            self.logger.info(f"[CLI].run Command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False) # check=False to handle non-zero exits manually

            if result.stderr:
                self.logger.warning(f"[CLI].run stderr: {result.stderr.strip()}")
            
            if result.stdout:
                self.logger.info(f"[CLI].run: returned code {result.returncode}")
                self.logger.debug(f"[CLI].run stdout: {result.stdout.strip()[:500]}...") # Log a snippet
            else: # No stdout, could be an error or command that doesn't produce stdout
                self.logger.info(f"[CLI].run: returned code {result.returncode} with no stdout.")
                if result.returncode != 0 and not result.stderr: # Error but no stderr
                    self.logger.error(f"[CLI].run: Command failed with code {result.returncode} but no stderr/stdout.")
            return result

        except FileNotFoundError:
            self.logger.error(f"[CLI].run Error: Snyk command not found. Ensure Snyk CLI is installed and in PATH.")
            exit(1)
        except Exception as e:
            self.logger.error(f"[CLI].run Error: {e}")
            traceback.print_exc()
            exit(1) # Or return None / raise depending on desired error handling

    def find_assets_from_repository_url(self, repository_url: Optional[str] = None) -> List[Asset]:
        '''
        Find the Asset from the repository_url
        :param repository_url:
        :return: Asset objects
        '''
        if not repository_url:
            self.logger.warning("[CLI].find_assets_from_repository_url: repository_url is None. Cannot find assets.")
            return []

        query = {
            "query": {
                "attributes": {
                    "operator": "and",
                    "values": [
                        {
                            "attribute": "type",
                            "operator": "equal",
                            "values": ["repository"]
                        },
                        {
                            "attribute": "name",
                            "operator": "contains",
                            "values": [repository_url.split('/')[-1]]
                        }
                    ]
                }
            }
        }
        self.assets = self.group.get_assets(query=query)
        if not self.assets: # self.assets could be None or an empty list
            self.logger.warning(f"[CLI].find_assets_from_repository_url No assets found for {repository_url}")
            return []
        self.logger.info(f"[CLI].find_assets_from_repository_url Found {len(self.assets)} assets for {repository_url}")
        return self.assets

    def find_org_id_from_asset(self, asset: Optional[Asset] = None) -> Optional[str]:
        """
        Get the orgId from the Asset object
        :param asset: Asset object
        :return: orgId or None
        """
        if not asset or not asset.organizations:
            self.logger.warning(f"[CLI].find_org_id_from_asset: Asset is None or has no organizations. Asset ID: {asset.id if asset else 'N/A'}")
            return None

        org_id = None
        if len(asset.organizations) > 1:
            self.logger.warning(f"[CLI].find_org_id_from_assets [Asset: {asset.id}] associated with more than one "
                                f"organization. Please specify index of the organization ID from the following: "
                                f"{[org.id for org in asset.organizations]}")
            # Potentially return the first one or None, depending on desired behavior for multiple orgs
            # For now, returning None to force disambiguation if this case is critical.
            # org_id = asset.organizations[0].id # Or handle as an error / prompt
        elif len(asset.organizations) == 1:
            org_id = asset.organizations[0].id
            self.logger.info(f"[CLI].find_org_id_from_assets [Asset: {asset.id}] matched with [Organization: {org_id}]")
        else: # len(asset.organizations) == 0
            self.logger.warning(
                f"[CLI].find_org_id_from_assets [Asset: {asset.id}] not associated with any organization.")
        return org_id

    def get_business_criticality_from_asset(self, asset: Optional[Asset] = None) -> Optional[str]:
        '''
        Get the business criticality mapping from the Asset's asset_class
        :param asset:
        :return: Criticality as a string or None
        '''
        if not asset or not hasattr(asset, 'asset_class') or not asset.asset_class or 'rank' not in asset.asset_class:
            self.logger.warning(f"[CLI].get_business_criticality_from_asset: Asset {asset.id if asset else 'N/A'} has no asset_class or rank.")
            return None
        try:
            rank = int(asset.asset_class.get('rank'))
            mapping = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
            return mapping.get(rank)
        except (ValueError, TypeError):
            self.logger.warning(f"[CLI].get_business_criticality_from_asset: Invalid rank '{asset.asset_class.get('rank')}' for asset {asset.id}.")
            return None


    def get_lifecycle_from_asset(self, asset: Optional[Asset] = None) -> Optional[str]:
        '''
        Get the lifecycle mapping from the Asset's app_lifecycle
        :param asset:
        :return: Lifecycle as a string or None
        '''
        if not asset or not hasattr(asset, 'app_lifecycle'):
            self.logger.warning(f"[CLI].get_lifecycle_from_asset: Asset {asset.id if asset else 'N/A'} has no app_lifecycle attribute.")
            return None

        if asset.app_lifecycle and asset.app_lifecycle in ['production', 'development', 'sandbox']:
            return asset.app_lifecycle
        elif asset.app_lifecycle is None:
            self.logger.warning(f"[CLI].get_lifecycle_from_asset No lifecycle found for asset {asset.id}.")
            return None # Explicitly return None
        else:
            self.logger.warning(
                f"[CLI].get_lifecycle_from_asset asset.app_lifecycle definition ('{asset.app_lifecycle}') is incompatible for asset "
                f"{asset.id}. Defaulting to 'Development'")
            return 'Development' # Or None if default is not desired
