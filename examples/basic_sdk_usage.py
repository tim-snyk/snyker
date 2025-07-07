"""
examples/basic_sdk_usage.py

This script demonstrates basic usage of the Snyk SDK (snyker) to interact
with the Snyk API. It covers:
- Initializing the APIClient and Group.
- Fetching organizations, projects, and issues.
- Querying for assets.
- Retrieving a specific asset by ID.
- Accessing raw API response data.
- Closing the API client.

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN environment variable with a Snyk Group-scoped Service Account token.
"""

from snyker import (
    GroupPydanticModel,
    APIClient,
    Asset,
    OrganizationPydanticModel,
    ProjectPydanticModel,
    IssuePydanticModel,
)
from typing import List, Optional
import json
import os


def shorten_project_name(name: str, max_len_after_colon: int = 30) -> str:
    """Shortens a project name if it contains a colon and long path.

    Example: "group/repo(branch):path/to/very/long/file.tf"
    becomes "group/repo(branch):.../file.tf"
    """
    if ":" in name:
        prefix, suffix_path = name.split(":", 1)
        if "/" in suffix_path:
            path_parts = suffix_path.split("/")
            if len(path_parts) > 2:  # Only shorten if there's a middle part
                # Check if the shortened version is actually shorter
                shortened_suffix = ".../" + path_parts[-1]
                if len(prefix + ":" + shortened_suffix) < len(name):
                    return prefix + ":" + shortened_suffix
    return name


import argparse

def main():
    """
    Demonstrates core functionalities of the snyker SDK.
    """
    parser = argparse.ArgumentParser(description="Demonstrate basic Snyk SDK usage.")
    parser.add_argument(
        "--loading-strategy",
        choices=["lazy", "eager"],
        default="lazy",
        help="The loading strategy to use for the SDK.",
    )
    args = parser.parse_args()

    from snyker.config import API_CONFIG
    API_CONFIG["loading_strategy"] = args.loading_strategy
    
    # Check for SNYK_TOKEN
    snyk_token = os.getenv("SNYK_TOKEN")
    if not snyk_token:
        print("Error: SNYK_TOKEN environment variable not set.")
        print("Please set it with your Snyk Group-scoped Service Account token.")
        return

    print("Initializing Snyk APIClient and Group...")
    # Initialize the APIClient with custom settings (optional, defaults can be used)
    # Logging level: 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL
    api_client = APIClient(
        max_retries=5, backoff_factor=0.5, logging_level=30  # Set to WARNING
    )

    # Initialize the GroupPydanticModel using its factory method.
    # If group_id is not provided, it attempts to find a single group.
    # If multiple groups exist for the token, it will raise a ValueError.
    try:
        from snyker.config import EXAMPLES_CONFIG
        # Using a known test group ID for this example. Replace with your actual group ID if needed.
        test_group_id = EXAMPLES_CONFIG.get("group_id")
        group = GroupPydanticModel.get_instance(
            api_client=api_client, group_id=test_group_id
        )
        print(f"Successfully initialized Group: '{group.name}' (ID: {group.id})")
    except ValueError as e:
        print(f"Error initializing Group: {e}")
        print(
            "If multiple groups are found for your token, you may need to specify a 'group_id':"
        )
        print(
            "  ex: group = GroupPydanticModel.get_instance(api_client=api_client, group_id='your-group-id')"
        )
        api_client.close()
        return

    # --- Data Fetching with Running Counts ---
    print("\n--- Starting Data Fetching ---")
    fetched_data = {"group_name": group.name, "group_id": group.id, "organizations": []}
    total_orgs_fetched = 0
    total_projects_fetched = 0
    total_issues_fetched = 0

    try:
        print(f"Fetching organizations for Group: {group.name} (ID: {group.id})...")
        # Explicitly fetch all organizations.
        organizations: List[OrganizationPydanticModel] = group.organizations
        total_orgs_fetched = len(organizations)
        print(f"Fetched {total_orgs_fetched} organization(s).")

        for org_idx, org in enumerate(organizations):
            print(
                f"  Fetching projects for Organization {org_idx+1}/{total_orgs_fetched}: {org.name} (ID: {org.id})..."
            )
            # Explicitly fetch all projects for the organization.
            projects: List[ProjectPydanticModel] = org.projects
            current_org_projects_fetched = len(projects)
            total_projects_fetched += current_org_projects_fetched
            print(
                f"    Fetched {current_org_projects_fetched} project(s) for Org '{org.name}'."
            )

            org_data = {
                "name": org.name,
                "id": org.id,
                "projects": [],
                "total_issues_in_org": 0,
            }

            for proj_idx, proj in enumerate(projects):
                print(
                    f"      Fetching issues for Project {proj_idx+1}/{current_org_projects_fetched}: {shorten_project_name(proj.name)} (ID: {proj.id})..."
                )
                # Explicitly fetch all issues for the project.
                issues: List[IssuePydanticModel] = proj.issues
                project_issue_count = len(issues)

                total_issues_fetched += project_issue_count
                org_data["total_issues_in_org"] += project_issue_count

                first_issue_id_log = (
                    f", First issue ID: {issues[0].id}"
                    if issues
                    else ""
                )
                print(
                    f"        Fetched {project_issue_count} issue(s) for Project '{shorten_project_name(proj.name)}'{first_issue_id_log}."
                )

                org_data["projects"].append(
                    {
                        "name": proj.name,  # Store original name for potential full display
                        "display_name": shorten_project_name(proj.name),
                        "id": proj.id,
                        "type": proj.project_type,
                        "issue_count": project_issue_count,
                    }
                )
            fetched_data["organizations"].append(org_data)

        print("\n--- Data Fetching Complete ---")
        print(f"Total Organizations Fetched: {total_orgs_fetched}")
        print(f"Total Projects Fetched: {total_projects_fetched}")
        print(
            f"Total Issues Fetched (status: 'open,resolved', excluding license & cloud types client-side): {total_issues_fetched}"
        )

    except Exception as e:
        print(f"An error occurred during data fetching: {e}")
        import traceback

        traceback.print_exc()
        api_client.close()
        return

    # --- Generate Snyk Entity Summary from Fetched Data ---
    print("\n--- Snyk Entity Summary ---")
    try:
        print(f"Group: {fetched_data['group_name']} (ID: {fetched_data['group_id']})")
        print(f"  ├─ Organizations ({len(fetched_data['organizations'])}):")

        for org_idx, org_data in enumerate(fetched_data["organizations"]):
            is_last_org = org_idx == len(fetched_data["organizations"]) - 1
            org_prefix = "  │  " if not is_last_org else "     "
            org_branch = "  ├─" if not is_last_org else "  └─"

            print(
                f"{org_branch} Organization: {org_data['name']} (ID: {org_data['id']})"
            )
            print(f"{org_prefix}  ├─ Projects ({len(org_data['projects'])}):")

            for proj_idx, proj_data in enumerate(org_data["projects"]):
                is_last_proj = proj_idx == len(org_data["projects"]) - 1
                proj_branch = (
                    f"{org_prefix}  ├─" if not is_last_proj else f"{org_prefix}  └─"
                )

                # Removed issue_count from this line
                print(
                    f"{proj_branch} Project: {proj_data['display_name']} (ID: {proj_data['id']}, Type: {proj_data['type']})"
                )

            # Removed "Total Issues in Org" line
            if is_last_org:
                print(f"     └─ (End of Org '{org_data['name']}')")
            else:
                print(f"  │")

        print(
            f"\nTotal Issues in Group '{fetched_data['group_name']}': {total_issues_fetched}"
        )

    except Exception as e:
        print(f"An error occurred while printing the summary: {e}")
        import traceback

        traceback.print_exc()

    # --- Important: Close the APIClient when done ---
    print("\nClosing the API client...")
    api_client.close()  # Close the client instance created at the start
    print("API client closed. Script finished.")


if __name__ == "__main__":
    main()
