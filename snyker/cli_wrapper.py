# A Snyk CLI wrapper that calls Snyk APIs to retrieve context metadata and synchronize with Snyk Organization entities'
# settings and policies.
#
from __future__ import annotations
from typing import TYPE_CHECKING, List
from snyker import Group

if TYPE_CHECKING:
    from .asset import Asset

import os
import subprocess
import traceback
import json


class CLIWrapper:
    def __init__(self):
        self.project_directory = os.getenv('GITHUB_WORKSPACE') or os.getenv('CI_PROJECT_DIR') or os.getenv(
            'WORKSPACE') or os.getenv('BUILD_SOURCESDIRECTORY')
        self.org_id = None
        self.group = Group()
        self.api_client = self.group.api_client
        self.logger = self.api_client.logger
        self.assets = None

    def change_directory(self, directory: str = None):
        """
        Changes the current working directory to the git directory if set.
        :return:
        """
        if directory:
            os.chdir(directory)
            self.logger.info(f"[CLI].change_directory: {directory}")
        elif self.project_directory is not None:
            os.chdir(self.project_directory)
            self.logger.info(f"[CLI].change_directory: {directory}")
        else:
            self.logger.warning("GITHUB_WORKSPACE, CI_PROJECT_DIR, WORKSPACE or BUILD_SOURCESDIRECTORY environment "
                                "variables not set. Current directory remains unchanged.")

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

    def run(self, params: dict = {}, param_str: str = None) -> str:
        """
        Runs Snyk CLI in a subprocess and returns the stdout as string
        :return:
        """
        try:
            # Run Snyk code test and capture JSON output
            if param_str:
                command = param_str.split(' ')
            else:
                command = ['snyk']
                for key, value in params.items():
                    if value == ('' or None):
                        command.append(f'{key}')
                    else:
                        command.append(f'{key}={value}')
            self.logger.info(f"[CLI].run Command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True)
            # Debug run command by examining the output
            # Print output stream until subprocess returns
            self.logger.debug(f"[CLI].run stdout: {result.stdout}")
            if result.stdout:
                self.logger.info(f"[CLI].run: returned code {result.returncode} ")
            if result.stderr:
                self.logger.warning(result.stderr)
            else:
                self.logger.info(f"[CLI].run Completed running Snyk CLI with params: {' '.join(command)}")
                return result
        except Exception as e:
            self.logger.error(f"[CLI].run Error: {e}")
            traceback.print_exc()
            exit(1)

    def find_assets_from_repository_url(self, repository_url: str = None) -> List[Asset]:
        '''
        Find the Asset from the repository_url
        :param repository_url:
        :return: Asset objects
        '''
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
                            "values": [repository_url.split('/')[-1]]  # Extracting the repo name from the URL
                        }
                    ]
                }
            }
        }
        self.assets = self.group.get_assets(query=query)
        self.logger.info(f"[CLI].find_assets_from_repository_url Found {len(self.assets)} assets for {repository_url}")
        if self.assets is None:
            self.logger.warning(f"[CLI].find_assets_from_repository_url No assets found for {repository_url}")
            return None
        return self.assets

    def find_org_id_from_asset(self, asset: Asset = None) -> str:
        """
        Get the orgId from the Asset object
        :param asset: Asset object
        :return: orgId, None
        """
        org_id = None
        for asset in assets:
            if len(asset.organizations) > 1:
                self.logger.warning(f"[CLI].find_org_id_from_assets [Asset: {asset.id}]associated with more than one "
                                    f"organization. Please specify index of the organization ID from the following:"
                                    f" {asset.organizations}")
            elif len(asset.organizations) == 1:
                org_id = asset.organizations[0].id
                self.logger.info(f"[CLI].find_org_id_from_assets [Asset: {asset.id}] matched with [Organization: "
                                 f"{asset.organizations[0].id}")
                break
            else:
                self.logger.warning(
                    f"[CLI].find_org_id_from_assets {repository_url} not associated with any organization.")
        return org_id if org_id is not None else None

    def get_business_criticality_from_asset(self, asset: Asset = None):
        '''
        Get the business criticality mapping from the Asset's asset_class
        :param asset:
        :return: Criticality as a string
        '''
        return {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}[int(asset.asset_class.get('rank'))]

    def get_lifecycle_from_asset(self, asset: Asset = None):
        '''
        Get the lifecycle mapping from the Asset's app_lifecycle
        :param asset:
        :return: Lifecycle as a string
        '''
        if asset.app_lifecycle and asset.app_lifecycle in ['production', 'development', 'sandbox']:
            return asset.app_lifecycle
        elif asset.app_lifecycle is None:
            self.logger.warning(f"[CLI].get_lifecycle_from_asset No lifecycle found for asset {asset.id}.")
        else:
            self.logger.warning(
                f"[CLI].get_lifecycle_from_asset asset.app_lifecycle definition is incompatible for asset "
                f"{asset.id}. Defaulting to 'Development'")
            return 'Development'


if __name__ == "__main__":
    # Example usage
    snyk_cli = CLIWrapper()  # Instantiate the CLIWrapper class
    snyk_cli.flight_check(minimum_version='1.1295.4')  # Check Snyk CLI presence and version

    snyk_cli.change_directory(snyk_cli.project_directory)  # Change to your git repo directory
    # Get the orgId from the asset
    repository_url = 'https://github.com/tim-snyk/vulnado'
    assets = snyk_cli.find_assets_from_repository_url(repository_url)  # Find the asset(s) from the repository URL
    if len(assets) == 1:
        asset = assets[0]  # Assign it to singular Asset object
    org_id = snyk_cli.find_org_id_from_asset(asset)  # Find the org_id from the Asset object

    playbook = [
        {
            'test': None,
            '--org': org_id,
        },
        {
            'code': None,
            'test': None,
            '--org': org_id,
        },
        {
            'monitor': None,
            '--org': org_id,
            '--remote-repo-url': repository_url,
            '--tags': 'snyker=test,report=true',
            '--project-business-criticality': snyk_cli.get_business_criticality_from_asset(asset),
            '--project-lifecycle': snyk_cli.get_lifecycle_from_asset(asset),
            '--project-environment': 'backend'
        },
    ]
    # Run the playbook which is an extensible queue of commands to execute
    while len(playbook) > 0:
        task = playbook.pop(0)
        snyk_cli.run(task)  # Run the task with the Snyk CLI
    snyk_cli.change_directory('/Users/timgowan/git/juice-shop')  # Change to a specific git repo directory
    result = snyk_cli.run(param_str=f'snyk code test --org={org_id} --json')
    result = json.loads(result.stdout)  # Parse the JSON output
