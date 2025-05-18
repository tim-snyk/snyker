# A Snyk CLI wrapper that calls Snyk APIs to retrieve context metadata and synchronize with Snyk Organization entities'
# settings and policies.
#
# Check the following locations to identify Pipeline environment. $GITHUB_WORKSPACE, $CI_PROJECT_DIR, $WORKSPACE, $(Build.SourcesDirectory)
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

    def changeDirectory(self, directory: str = None):
        '''
        Changes the current working directory to the git directory if set.
        :return:
        '''
        if directory:
            os.chdir(directory)
            logger.info(f"Changed directory to {directory}")
        elif self.project_directory is None:
            os.chdir(self.project_directory)
            logger.info(f"Changed directory to {self.project_directory}")
        else:
            logger.warning("GITHUB_WORKSPACE, CI_PROJECT_DIR, WORKSPACE or BUILD_SOURCESDIRECTORY environment variable"
                           " not set. Current directory remains unchanged.")

    def version_check(self, version_minimum=None):
        try:
            result = subprocess.run(['snyk', '-v'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning(f"Error running Snyk CLI: {result.stderr}")
                exit(1)
            version = result.stdout.strip()
            logger.info(f"Snyk CLI version: {version}")
            if version_minimum and version < version_minimum:
                logger.warning(f"Snyk CLI version {version} is not supported. Please update to a newer version.")
                exit(1)
        except Exception as e:
            logger.error(f"Error in versionCheck: {e}")
            traceback.print_exc()
            exit(1)

    def run_snyk_cli(self, params: dict = {}, param_str: str = None) -> str:
        '''
        Runs Snyk CLI in a subprocess and returns the stdout as string
        :return:
        '''
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

    def find_org_id(self, repository_url: str):
        '''
        Find the orgId from the asset
        :param repository_url:
        :return:
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
        assets = group.get_assets(query=query)
        for asset in assets:
            if asset.browse_url == repository_url: # Matching asset against the full URL as provided
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


if __name__ == "__main__":
    # Example usage

    snyk_cli = SnykCliWrapper()  # Instantiate the SnykCliWrapper class
    snyk_cli.version_check()  # Check Snyk CLI version
    snyk_cli.changeDirectory(snyk_cli.project_directory)  # Change to your git repo directory

    # Get the orgId from the asset
    repository_url = 'https://github.com/tim-snyk/vulnado'
    org_id = snyk_cli.find_org_id(repository_url)  # Find the orgId from the asset

    playbook = [
        {
            'test': None,
            '--org': org_id,
        },
        {
            'monitor': None,
            '--org': org_id,


        },
        {
            'code': None,
            'test': None,
            '--org': org_id,
        },
    ]
    # Run the playbook which is an extensible queue of commands to execute
    while len(playbook) > 0:
        task = playbook.pop(0)
        snyk_cli.run_snyk_cli(task)  # Run the task with the Snyk CLI
    snyk_cli.changeDirectory('/Users/timgowan/git/juice-shop')  # Change to a specific git repo directory
    result = snyk_cli.run_snyk_cli(param_str=f'snyk code test --org={org_id} --json')
    result = json.loads(result)  # Parse the JSON output
    #print(json.dumps(result, indent=4, sort_keys=True, default=str))
