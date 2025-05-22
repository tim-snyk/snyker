from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional, Dict
if TYPE_CHECKING:
    from snyker import Asset, APIClient

from snyker import GroupPydanticModel
import os
import subprocess
import traceback
import json


class CLIWrapper:
    """A wrapper for interacting with the Snyk Command Line Interface (CLI).

    This class provides methods to execute Snyk CLI commands, manage project
    directories, and perform common Snyk operations by leveraging the CLI.
    It can also interact with Snyk API models for richer context.

    Attributes:
        api_client: An instance of `snyker.APIClient` for API interactions.
        logger: A logger instance inherited from the `api_client`.
        group: An instance of `snyker.GroupPydanticModel` representing the Snyk Group.
        assets: A list of `snyker.Asset` instances, typically populated by
            `find_assets_from_repository_url`.
        project_directory: The file system path to the project being analyzed.
            Can be auto-detected from CI environment variables or overridden.
        org_id: The Snyk Organization ID, often determined from an asset.
    """
    def __init__(self,
                 group: Optional[GroupPydanticModel] = None,
                 project_directory_override: Optional[str] = None,
                 api_client: Optional[APIClient] = None):
        """Initializes the CLIWrapper.

        Args:
            group: An optional `GroupPydanticModel` instance. If not provided,
                it attempts to initialize one using `GroupPydanticModel.get_instance()`.
            project_directory_override: An optional string to explicitly set the
                project directory. If None, attempts to auto-detect from CI
                environment variables.
            api_client: An optional `APIClient` instance. If not provided,
                a default one is created.
        
        Raises:
            ValueError: If `GroupPydanticModel.get_instance()` fails when `group`
                is not provided (e.g., multiple groups found for the token).
        """
        self.org_id = None
        
        if api_client:
            self.api_client = api_client
        else:
            self.api_client = APIClient()

        self.logger = self.api_client.logger

        if group:
            self.group = group
        else:
            try:
                self.group = GroupPydanticModel.get_instance(api_client=self.api_client)
            except ValueError as e:
                self.logger.error(f"Failed to initialize Group in CLIWrapper: {e}")
                raise
        
        self.assets: Optional[List[Asset]] = None 
        self.project_directory: Optional[str] = None

        if project_directory_override:
            self.project_directory = project_directory_override
            self.logger.info(f"Using explicitly provided project directory: {self.project_directory}")
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
                        f"Detected {detected_ci_env} environment. "
                        f"Using project directory: {self.project_directory} (from ${var_name})"
                    )
                    break
            
            if not self.project_directory:
                checked_vars_str = ", ".join([f"${var}" for var, _ in known_ci_vars])
                self.logger.warning(
                    f"Could not automatically determine project directory from known CI/CD "
                    f"environment variables. Checked: {checked_vars_str}. "
                    "Current directory will be used if not explicitly changed by change_directory()."
                )

    def change_directory(self, directory: Optional[str] = None) -> None:
        """Changes the current working directory.

        If `directory` is provided, changes to that directory. Otherwise, if
        `self.project_directory` is set (either auto-detected or overridden),
        changes to that directory. If neither is available, a warning is logged
        and the directory remains unchanged.

        Args:
            directory: The optional path to change the working directory to.
        """
        if directory:
            os.chdir(directory)
            self.logger.info(f"Changed working directory to: {directory}")
        elif self.project_directory is not None:
            os.chdir(self.project_directory)
            self.logger.info(f"Changed working directory to project directory: {self.project_directory}")
        else:
            self.logger.warning(
                "No project directory specified or auto-detected. Current directory remains unchanged."
            )

    def flight_check(self, minimum_version: Optional[str] = None) -> None:
        """Checks if the Snyk CLI is installed and meets an optional minimum version.

        Exits the program if the CLI is not found, fails to run, or does not meet
        the minimum version requirement.

        Args:
            minimum_version: An optional string specifying the minimum required
                version of the Snyk CLI (e.g., "1.1000.0").
        """
        try:
            result = subprocess.run(['snyk', '-v'], capture_output=True, text=True, check=False)
            if result.returncode == 127: # Command not found
                self.logger.error("Snyk CLI not found. Please install Snyk CLI.")
                exit(1)
            if result.returncode != 0:
                self.logger.error(f"Error running Snyk CLI: {result.stderr}")
                exit(1)
            version = result.stdout.strip()
            self.logger.info(f"Using Snyk CLI version {version}")
            if minimum_version and version < minimum_version:
                self.logger.error(f"Snyk CLI version {version} is not supported. "
                                  f"Please update to {minimum_version} or greater.")
                exit(1)
        except Exception as e:
            self.logger.error(f"Error during Snyk CLI flight check: {e}")
            traceback.print_exc()
            exit(1)

    def run(self, params: Optional[Dict[str, str]] = None, param_str: Optional[str] = None) -> subprocess.CompletedProcess:
        """Runs a Snyk CLI command and returns the result.

        The command can be specified either as a dictionary of parameters (e.g.,
        `{'test': None, '--json': None, '--file': 'package.json'}`) or as a
        pre-formatted string.

        Args:
            params: A dictionary where keys are command flags (e.g., '--json')
                and values are their arguments. If a value is empty string or None,
                the flag is treated as a boolean flag.
            param_str: A string representing the full Snyk command (e.g.,
                "snyk test --json --file=package.json"). If provided, `params`
                is ignored.

        Returns:
            A `subprocess.CompletedProcess` object containing the result of the
            command execution.

        Raises:
            SystemExit: If the Snyk CLI command is not found or an unexpected
                error occurs during execution.
        """
        try:
            if param_str:
                command = param_str.split(' ')
            else:
                command = ['snyk']
                if params:
                    for key, value in params.items():
                        if value == '' or value is None:
                            command.append(f'{key}')
                        else:
                            command.append(f'{key}={value}')
            
            self.logger.info(f"Running Snyk CLI command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False)

            if result.stderr:
                self.logger.warning(f"Snyk CLI stderr: {result.stderr.strip()}")
            
            if result.stdout:
                self.logger.info(f"Snyk CLI returned code {result.returncode}")
                self.logger.debug(f"Snyk CLI stdout (first 500 chars): {result.stdout.strip()[:500]}...")
            else:
                self.logger.info(f"Snyk CLI returned code {result.returncode} with no stdout.")
                if result.returncode != 0 and not result.stderr:
                    self.logger.error(f"Snyk CLI command failed with code {result.returncode} but no stderr/stdout.")
            return result

        except FileNotFoundError:
            self.logger.error("Snyk CLI command not found. Ensure Snyk CLI is installed and in PATH.")
            exit(1) # Consider raising an exception instead of exiting
        except Exception as e:
            self.logger.error(f"Error running Snyk CLI command: {e}")
            traceback.print_exc()
            exit(1) # Consider raising an exception

    def find_assets_from_repository_url(self, repository_url: Optional[str] = None) -> List[Asset]:
        """Finds Snyk assets matching a given repository URL.

        Args:
            repository_url: The URL of the repository to search for.

        Returns:
            A list of `Asset` objects matching the repository URL, or an empty
            list if none are found or if `repository_url` is not provided.
        """
        if not repository_url:
            self.logger.warning("repository_url is None. Cannot find assets.")
            return []

        repo_name_segment = repository_url.split('/')[-1]
        query = {
            "query": {
                "attributes": {
                    "operator": "and",
                    "values": [
                        {"attribute": "type", "operator": "equal", "values": ["repository"]},
                        {"attribute": "name", "operator": "contains", "values": [repo_name_segment]}
                    ]
                }
            }
        }
        
        self.assets = self.group.get_assets_by_query(query=query)
        if not self.assets:
            self.logger.warning(f"No assets found for repository URL: {repository_url}")
            return []
        self.logger.info(f"Found {len(self.assets)} assets for repository URL: {repository_url}")
        return self.assets

    def find_org_id_from_asset(self, asset: Optional[Asset] = None) -> Optional[str]:
        """Extracts the Snyk Organization ID from an Asset object.

        If the asset is associated with multiple organizations, a warning is logged,
        and `None` is returned to indicate ambiguity.

        Args:
            asset: An `Asset` object.

        Returns:
            The Snyk Organization ID as a string if a single organization is found,
            otherwise `None`.
        """
        if not asset or not asset.organizations: # asset.organizations uses the property
            asset_id_log = asset.id if asset else "N/A"
            self.logger.warning(f"Asset is None or has no organizations. Asset ID: {asset_id_log}")
            return None

        org_id = None
        if len(asset.organizations) > 1:
            org_ids_str = ", ".join([org.id for org in asset.organizations])
            self.logger.warning(f"Asset {asset.id} associated with multiple organizations: [{org_ids_str}]. "
                                "Cannot determine a single org_id.")
        elif len(asset.organizations) == 1:
            org_id = asset.organizations[0].id
            self.logger.info(f"Asset {asset.id} matched with Organization ID: {org_id}")
        else: # len(asset.organizations) == 0
            self.logger.warning(f"Asset {asset.id} not associated with any organization.")
        return org_id

    def get_business_criticality_from_asset(self, asset: Optional[Asset] = None) -> Optional[str]:
        """Gets the business criticality mapping from an Asset's attributes.

        Args:
            asset: An `Asset` object.

        Returns:
            The business criticality as a string ('critical', 'high', 'medium', 'low')
            or `None` if not determinable.
        """
        if not asset or not asset.attributes.class_data or 'rank' not in asset.attributes.class_data:
            asset_id_log = asset.id if asset else "N/A"
            self.logger.warning(f"Asset {asset_id_log} has no class_data or rank in attributes.")
            return None
        try:
            rank = int(asset.attributes.class_data['rank'])
            mapping = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
            return mapping.get(rank)
        except (ValueError, TypeError):
            self.logger.warning(f"Invalid rank '{asset.attributes.class_data.get('rank')}' for asset {asset.id}.")
            return None


    def get_lifecycle_from_asset(self, asset: Optional[Asset] = None) -> Optional[str]:
        """Gets the lifecycle mapping from an Asset's attributes.

        Args:
            asset: An `Asset` object.

        Returns:
            The lifecycle stage as a string ('production', 'development', 'sandbox'),
            defaults to 'Development' if incompatible, or `None` if not set.
        """
        lifecycle = asset.attributes.app_lifecycle if asset and asset.attributes else None
        
        if lifecycle is None:
            asset_id_log = asset.id if asset else "N/A"
            self.logger.warning(f"Asset {asset_id_log} has no app_lifecycle attribute or is None.")
            return None

        if lifecycle in ['production', 'development', 'sandbox']:
            return lifecycle
        else:
            asset_id_log = asset.id if asset else "N/A"
            self.logger.warning(
                f"Asset attribute app_lifecycle ('{lifecycle}') is incompatible for asset "
                f"{asset_id_log}. Defaulting to 'Development'."
            )
            return 'Development'
