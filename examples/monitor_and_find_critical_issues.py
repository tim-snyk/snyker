"""
examples/monitor_and_find_critical_issues.py

This script demonstrates a workflow that combines the Snyk CLI and API for CI/CD gating:
1. It uses the CLIWrapper to run `snyk monitor` on a specified local project directory.
2. It parses the JSON output from the CLI to get the URI of the monitored project,
   and then extracts the project ID from the URI.
3. It then uses the Snyk SDK to query the API for all 'high' or 'critical' severity
   issues associated with that project.
4. Finally, it applies a "fail-open" policy: if any of the found issues are older
   than a specified number of days, the script exits with a "fail" status (exit code 1),
   otherwise it "passes" (exit code 0).

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN and SNYK_GROUP_ID environment variables.

Usage:
poetry run python examples/monitor_and_find_critical_issues.py --repository-url <URL>
"""
import argparse
import configparser
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import List

from snyker import APIClient, CLIWrapper, GroupPydanticModel, IssuePydanticModel, ProjectPydanticModel

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_violating_issues(issues: List[IssuePydanticModel], days_threshold: int) -> List[IssuePydanticModel]:
    """
    Finds all issues that are older than the specified threshold and not ignored.

    Args:
        issues: A list of IssuePydanticModel objects.
        days_threshold: The age in days to check against.

    Returns:
        A list of issues that violate the policy.
    """
    now = datetime.now(timezone.utc)
    threshold_datetime = now - timedelta(days=days_threshold)
    violating_issues = []

    for issue in issues:
        if issue.attributes.ignored:
            continue

        attrs = issue.attributes
        
        # First, check the disclosed and discovered dates
        if attrs.problems:
            for problem in attrs.problems:
                if problem.disclosed_at and problem.disclosed_at < threshold_datetime:
                    violating_issues.append(issue)
                    continue
                if problem.discovered_at and problem.discovered_at < threshold_datetime:
                    violating_issues.append(issue)
                    continue

        # If not already added, check the modification times
        if issue not in violating_issues:
            timestamps = [
                attrs.created_at,
                attrs.updated_at,
            ]
            if attrs.problems:
                for problem in attrs.problems:
                    timestamps.append(problem.updated_at)
            if attrs.severities:
                for severity in attrs.severities:
                    timestamps.append(severity.modification_time)

            for ts in timestamps:
                if ts and ts < threshold_datetime:
                    violating_issues.append(issue)
                    break
    
    return violating_issues

def get_repo_url_from_git_config(project_directory: str) -> str | None:
    """
    Reads the remote repository URL from the .git/config file.

    Args:
        project_directory: The path to the project directory.

    Returns:
        The repository URL if found, otherwise None.
    """
    git_config_path = os.path.join(project_directory, ".git", "config")
    if not os.path.exists(git_config_path):
        return None

    config = configparser.ConfigParser()
    config.read(git_config_path)

    try:
        url = config.get('remote "origin"', "url")
        if url.endswith(".git"):
            url = url[:-4]
        return url
    except (configparser.NoSectionError, configparser.NoOptionError):
        return None

def main():
    """
    Main function to monitor a project and apply a time-based issue policy.
    """
    parser = argparse.ArgumentParser(description="Monitor a project and apply a time-based issue policy.")
    parser.add_argument("--project-directory", default=".", help="The path to the project to be scanned.")
    parser.add_argument("--repository-url", help="The URL of the remote repository.")
    parser.add_argument("--fail-open-days", type=int, default=30, help="The number of days for the time-based policy.")
    args = parser.parse_args()

    project_directory = args.project_directory
    repository_url = args.repository_url
    fail_open_days = args.fail_open_days
    snyk_group_id = os.getenv("SNYK_GROUP_ID")

    if not snyk_group_id:
        logger.error("SNYK_GROUP_ID environment variable must be set.")
        sys.exit(1)

    if not repository_url:
        repository_url = get_repo_url_from_git_config(project_directory)
        if not repository_url:
            logger.error("Could not determine repository URL from .git/config. Please provide it with --repository-url.")
            sys.exit(1)

    logger.info("Initializing Snyk API Client and Group...")
    api_client = APIClient()
    group = GroupPydanticModel.get_instance(api_client=api_client, group_id=snyk_group_id)
    snyk_cli = CLIWrapper(group=group, api_client=api_client)

    # --- 1. Run `snyk monitor` ---
    logger.info(f"Finding Snyk asset for repository URL: {repository_url} to determine Org ID.")
    assets = snyk_cli.find_assets_from_repository_url(repository_url)
    if not assets:
        logger.error(f"No Snyk asset found for repository: {repository_url}")
        sys.exit(1)
    
    asset_with_single_org = next((a for a in assets if len(a.organizations) == 1), None)
    if not asset_with_single_org:
        logger.error(f"Could not find an asset for {repository_url} with a single organization.")
        sys.exit(1)

    org_id = asset_with_single_org.organizations[0].id
    logger.info(f"Determined Organization ID: {org_id}")
    print(f"\n--- Organization Details ---")
    print(f"  Name: {asset_with_single_org.organizations[0].name}")
    print(f"  ID: {org_id}")
    print(f"--------------------------")

    snyk_cli.change_directory(project_directory)
    monitor_params = {'monitor': None, '--json': None, '--org': org_id, '--remote-repo-url': repository_url}
    
    logger.info("Executing `snyk monitor`...")
    result = snyk_cli.run(params=monitor_params)

    if result.returncode != 0:
        logger.error(f"`snyk monitor` failed. Stderr: {result.stderr}")
        sys.exit(1)

    try:
        monitor_output = json.loads(result.stdout)
        uri = monitor_output.get("uri")
        if not uri:
            logger.error("Could not find 'uri' in `snyk monitor` JSON output.")
            sys.exit(1)
        
        project_id = uri.split('/project/')[1].split('/')[0]
        logger.info(f"Successfully monitored. Snyk Project ID: {project_id}")
        print(f"\nProject monitored: {monitor_output.get('projectName')} ({uri})")

    except (json.JSONDecodeError, IndexError) as e:
        logger.error(f"Failed to parse project ID from `snyk monitor` output: {e}\nRaw stdout: {result.stdout}")
        sys.exit(1)

    # --- 2. Fetch Project and Issues from API ---
    try:
        # First, we need the organization object to fetch the project
        organization = asset_with_single_org.organizations[0]
        project = ProjectPydanticModel.from_api_response(
            project_data={'id': project_id},
            api_client=api_client,
            organization=organization,
            fetch_full_details_if_summary=True
        )

        if project.status != 'active':
            logger.warning(f"Project {project.name} (ID: {project.id}) is not active. Status: {project.status}")

        print(f"\n--- Project Details ---")
        print(f"  Name: {project.name}")
        print(f"  ID: {project.id}")
        print(f"  Status: {project.status}")
        print(f"  Origin: {project.origin}")
        print(f"  Type: {project.project_type}")
        print(f"-----------------------")

        logger.info(f"Fetching issues for project: {project.name} (ID: {project.id})")
        
        # Poll for issues to allow the backend to populate them
        all_issues = []
        for i in range(5): # Poll up to 5 times
            all_issues = project.fetch_issues()
            if all_issues:
                break
            logger.info(f"No issues found yet, polling again in 5 seconds... (Attempt {i+1}/5)")
            time.sleep(5)

        if not all_issues:
            print("\nNo issues found for this project after polling. Policy PASS.")
            logger.info("No issues found for this project after polling. Policy PASS.")
            sys.exit(0)

        print(f"\n--- Found {len(all_issues)} Issues for Project ID: {project_id} ---")

        # --- 3. Apply Logic and Determine Pass/Fail ---
        critical_high_issues = [
            issue for issue in all_issues 
            if issue.attributes.effective_severity_level in ['critical', 'high']
        ]
        
        violating_issues = get_violating_issues(critical_high_issues, fail_open_days)

        if violating_issues:
            print(f"\nCI/CD GATE: FAIL - Found {len(violating_issues)} critical/high issues older than {fail_open_days} days:")
            for issue in violating_issues:
                attrs = issue.attributes
                print(f"\n-----------------------------------------")
                print(f"  Title: {attrs.title}")
                print(f"  Issue ID: {issue.id}")
                print(f"  Severity: {attrs.effective_severity_level.capitalize() if attrs.effective_severity_level else 'N/A'}")
                print(f"  Type: {attrs.type}")
                print(f"  Ignored: {attrs.ignored}")
                print("\n  --- Timestamps ---")
                print(f"    Issue Created At: {attrs.created_at.isoformat() if attrs.created_at else 'N/A'}")
                print(f"    Issue Updated At: {attrs.updated_at.isoformat() if attrs.updated_at else 'N/A'}")
                if attrs.problems:
                    for i, problem in enumerate(attrs.problems):
                        if problem.source == 'NVD':
                            print(f"    NVD Last Modified: {problem.updated_at.isoformat() if problem.updated_at else 'N/A'}")
                        else:
                            print(f"    Problem ({problem.source}) Updated At: {problem.updated_at.isoformat() if problem.updated_at else 'N/A'}")
                print(f"-----------------------------------------")
            sys.exit(1)
        else:
            print(f"\nCI/CD GATE: PASS - No critical/high issues are older than {fail_open_days} days.")
            sys.exit(0)

    except Exception as e:
        logger.error(f"An error occurred during issue fetching or policy check: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Closing API client.")
        api_client.close()

if __name__ == "__main__":
    main()
