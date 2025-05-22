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
from snyker import Group, APIClient
import json
import os # For SNYK_TOKEN check

def main():
    """
    Demonstrates core functionalities of the snyker SDK.
    """

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
        max_retries=5,
        backoff_factor=0.5,
        logging_level=20  # Set to INFO for this example
    )

    # Initialize the Group. If group_id is not provided, it attempts to find
    # a single group associated with the token.
    # If multiple groups exist, you'll need to provide a specific group_id.
    try:
        group = Group(api_client=api_client)
        print(f"Successfully initialized Group: '{group.name}' (ID: {group.id})")
    except ValueError as e:
        print(f"Error initializing Group: {e}")
        print("If multiple groups are found, you may need to specify a 'group_id' when creating the Group object:")
        print("  ex: group = Group(group_id='your-group-id', api_client=api_client)")
        api_client.close()
        return

    # --- Fetching Organizations, Projects, and Issues ---
    print("\nFetching organizations, projects, and issues...")
    try:
        # Fetch organizations. You can pass parameters, e.g., to filter by slug.
        # Replace 'your-org-slug' with an actual slug if you want to test filtering.
        # For this example, we fetch all orgs in the group.
        organizations = group.get_orgs() # params={'slug': 'your-org-slug'}
        print(f"Found {len(organizations)} organization(s) in group '{group.name}'.")

        all_project_issues = []
        for org in organizations:
            print(f"\n  Organization: '{org.name}' (ID: {org.id})")
            # Fetch projects within the organization.
            # Replace 'cli' with other origins if needed, or remove for all projects.
            projects = org.get_projects() # params={'origins': 'cli'}
            print(f"    Found {len(projects)} project(s) in organization '{org.name}'.")

            for proj in projects:
                print(f"      Project: '{proj.name}' (ID: {proj.id})")
                # print(f"        Raw project data (first 500 chars): {json.dumps(proj.raw['data'], indent=2)[:500]}...")

                # Fetch issues for each project
                issues = proj.get_issues()
                print(f"        Found {len(issues)} issue(s) for project '{proj.name}'.")
                if issues:
                    all_project_issues.extend(issues)
                    # print(f"          First issue ID (if any): {issues[0].id}")

        print(f"\nTotal issues collected from all projects: {len(all_project_issues)}")

    except Exception as e:
        print(f"An error occurred while fetching orgs/projects/issues: {e}")

    # --- Fetching Issues directly from the Group with parameters ---
    print("\nFetching 'code' issues (ignored=True) directly from the group...")
    try:
        # This demonstrates fetching issues at the group level with specific filters.
        # Note: This will overwrite group.issues if it was populated by other means.
        # If you want to append, manage the list separately.
        group_code_issues = group.get_issues(
            params={
                'type': "code",      # e.g., 'code', 'license', 'vuln'
                'ignored': True      # e.g., True, False
                # Add other parameters as needed, see Snyk API docs for /issues endpoint
            }
        )
        print(f"Found {len(group_code_issues)} 'code' issues (ignored=True) in the group.")
        if group_code_issues:
            print(f"  Example issue ID: {group_code_issues[0].id}, Key Asset: {getattr(group_code_issues[0], 'key_asset', 'N/A')}")

    except Exception as e:
        print(f"An error occurred while fetching group-level issues: {e}")

    # --- Fetching Assets ---
    print("\nFetching assets matching a query (e.g., 'repository' type with 'snyker' in name)...")
    # Replace with a query relevant to your Snyk assets.
    # Asset types can be 'repository', 'image', 'package', etc.
    asset_query = {
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
                        "values": ["snyker"] # Modify this to match an asset name in your group
                    }
                ]
            }
        }
    }
    try:
        assets = group.get_assets(query=asset_query)
        print(f"Found {len(assets)} asset(s) matching the query.")
        if assets:
            example_asset = assets[0]
            print(f"  Example asset: '{example_asset.name}' (ID: {example_asset.id}, Type: {example_asset.type})")

            # Accessing raw data (the full JSON response for the asset)
            # print(f"    Raw asset data (first 500 chars): {json.dumps(example_asset.raw, indent=2)[:500]}...")

            # Fetching related entities for an asset
            print(f"    Fetching projects related to asset '{example_asset.name}'...")
            asset_projects = example_asset.get_projects()
            print(f"      Found {len(asset_projects)} project(s) for this asset.")

            print(f"    Fetching organizations related to asset '{example_asset.name}'...")
            asset_orgs = example_asset.get_orgs()
            print(f"      Found {len(asset_orgs)} organization(s) for this asset.")

            # --- Fetching a Single Asset by ID ---
            print(f"\nFetching a single asset by its ID ('{example_asset.id}')...")
            specific_asset = group.get_asset(asset_id=example_asset.id)
            if specific_asset:
                print(f"  Successfully fetched asset: '{specific_asset.name}'")
            else:
                print(f"  Could not fetch asset with ID: {example_asset.id}")
        else:
            print("  No assets found matching the query. Try adjusting the 'name' in asset_query.")

    except Exception as e:
        print(f"An error occurred while fetching assets: {e}")

    # --- Important: Close the APIClient when done ---
    # This ensures background threads (like for concurrent API calls) are cleaned up.
    print("\nClosing the API client...")
    group.api_client.close()
    print("API client closed. Script finished.")


if __name__ == "__main__":
    main()
