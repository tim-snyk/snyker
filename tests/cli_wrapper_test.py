from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional
from snyker import CLIWrapper



if TYPE_CHECKING:
    from snyker import Asset
import json

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
    sarif = json.loads(result.stdout)  # Process the output as json object
