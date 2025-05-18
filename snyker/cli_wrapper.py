# A Snyk CLI wrapper that calls Snyk APIs to retrieve context metadata and synchronize with Snyk Organization entities'
# settings and policies.
#
from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional

if TYPE_CHECKING:
    from .asset import Asset

import os
import subprocess
import traceback
import json
import logging
from snyker import Group

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CLIWrapper:
    def __init__(self):
        self.project_directory = os.getenv('GITHUB_WORKSPACE') or os.getenv('CI_PROJECT_DIR') or os.getenv(
            'WORKSPACE') or os.getenv('BUILD_SOURCESDIRECTORY')
        self.org_id = None
        self.group = Group()
        self.api_client = self.group.api_client
        self.logger = self.api_client.logger
        self.assets = None

    def changeDirectory(self, directory: str = None):
        """
        Changes the current working directory to the git directory if set.
        :return:
        """
        if directory:
            os.chdir(directory)
            logger.info(f"Changed directory to {directory}")
        elif self.project_directory is None:
            os.chdir(self.project_directory)
            logger.info(f"Changed directory to {self.project_directory}")
        else:
            logger.warning("GITHUB_WORKSPACE, CI_PROJECT_DIR, WORKSPACE or BUILD_SOURCESDIRECTORY environment variable"
                           " not set. Current directory remains unchanged.")

    def flight_check(self, minimum_version=None):
        try:
            result = subprocess.run(['snyk', '-v'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning(f"Error running Snyk CLI: {result.stderr}")
                exit(1)
            if result.returncode == 127:
                logger.warning("Snyk CLI not found. Please install Snyk CLI.")
                exit(1)
            version = result.stdout.strip()
            logger.info(f"Snyk CLI version: {version}")
            if minimum_version and version < minimum_version:
                logger.warning(f"Snyk CLI version {version} is not supported. Please update to {minimum_version} "
                               f"or greater.")
                exit(1)
        except Exception as e:
            logger.error(f"Error in flight_check: {e}")
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
            result = subprocess.run(command, capture_output=True, text=True)
            # Debug run command by examining the output
            logger.info(f"[CLI] Command: {' '.join(command)}")
            # Print output stream until subprocess returns

            if result.stdout:
                logger.info(result.stdout)
            if result.stderr:
                logger.warning(result.stderr)
            else:
                logger.info(f"[CLI] Completed running Snyk CLI with params: {' '.join(command)}")
                return result.stdout
        except Exception as e:
            logger.error(f"[CLI] Error in run_snyk_cli: {e}")
            traceback.print_exc()
            exit(1)

    def find_assets_from_repository_url(self, repository_url: str = None):
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
        logger.debug(f"[CLI].find_assets_from_repository_url Found {len(self.assets)} assets for {repository_url}")
        if self.assets is None:
            logger.warning(f"[CLI].find_assets_from_repository_url No assets found for {repository_url}")
            return None
        return self.assets

    def find_org_id_from_assets(self, assets: List[Asset] = None, repository_url: str = None):
        '''
        Get the orgId from the asset
        :param repository_url:
        :param assets:
        :return: orgId, None
        '''
        for asset in assets:
            if asset.browse_url == repository_url:  # Matching asset against the full URL as provided
                if len(asset.organizations) == 0:
                    logger.warning(f"[CLI].find_org_id {repository_url} not associated with any organization.")
                    return None
                if len(asset.organizations) > 1:
                    logger.warning(f"[CLI].find_org_id {repository_url} associated with more than one organization. "
                                   f"Please specify the organization ID from the following:"
                                   f" {asset.organizations}")
                    return None
        org_id = asset.organizations[0].get('id')
        logger.info(f"[CLI].find_org_id Found [Organization: {org_id}] for asset matching {repository_url}")
        return org_id

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
            logger.warning(f"[CLI].get_lifecycle_from_asset No lifecycle found for asset {asset.id}.")
        else:
            logger.warning(f"[CLI].get_lifecycle_from_asset asset.app_lifecycle definition is incompatible for asset "
                           f"{asset.id}. Defaulting to 'Development'")
            return 'Development'

if __name__ == "__main__":
    # Example usage
    snyk_cli = CLIWrapper()  # Instantiate the CLIWrapper class
    snyk_cli.flight_check(minimum_version='1.1295.4')  # Check Snyk CLI presence and version
    snyk_cli.changeDirectory(snyk_cli.project_directory)  # Change to your git repo directory

    # Get the orgId from the asset
    repository_url = 'https://github.com/tim-snyk/vulnado'
    assets = snyk_cli.find_assets_from_repository_url(repository_url)  # Find the asset from the repository URL
    org_id = snyk_cli.find_org_id_from_assets(assets)  # Find the orgId from the asset, also populates self.asset
    if len(assets) == 1:
        asset = assets[0]  # If only one asset is found, assign it to self.asset

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
    snyk_cli.changeDirectory('/Users/timgowan/git/juice-shop')  # Change to a specific git repo directory
    result = snyk_cli.run(param_str=f'snyk code test --org={org_id} --json')
    result = json.loads(result)  # Parse the JSON output
