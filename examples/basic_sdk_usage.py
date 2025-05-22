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
from snyker import GroupPydanticModel, APIClient, Asset, OrganizationPydanticModel, ProjectPydanticModel, IssuePydanticModel
from typing import List, Optional # Added List and Optional
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

    # Initialize the GroupPydanticModel using its factory method.
    # If group_id is not provided, it attempts to find a single group.
    # If multiple groups exist for the token, it will raise a ValueError.
    try:
        # Using a known test group ID for this example. Replace with your actual group ID if needed.
        test_group_id = "9365faba-3e72-4fda-9974-267779137aa6" 
        group = GroupPydanticModel.get_instance(api_client=api_client, group_id=test_group_id)
        print(f"Successfully initialized Group: '{group.name}' (ID: {group.id})")
    except ValueError as e:
        print(f"Error initializing Group: {e}")
        print("If multiple groups are found for your token, you may need to specify a 'group_id':")
        print("  ex: group = GroupPydanticModel.get_instance(api_client=api_client, group_id='your-group-id')")
        api_client.close()
        return

    # --- Fetching Organizations, Projects, and Issues ---
    print("\nFetching organizations, projects, and issues...")
    try:
        # Access organizations using the property (triggers lazy/eager loading based on config).
        # To pass specific fetch parameters, call the fetch_organizations() method directly.
        # Example: organizations = group.fetch_organizations(params={'slug': 'your-org-slug'})
        organizations: List[OrganizationPydanticModel] = group.organizations
        print(f"Found {len(organizations)} organization(s) in group '{group.name}'.")

        all_project_issues: List[IssuePydanticModel] = []
        for org in organizations:
            print(f"\n  Organization: '{org.name}' (ID: {org.id})")
            # Access projects for the organization.
            # Example: projects = org.fetch_projects(params={'origins': 'cli'})
            projects: List[ProjectPydanticModel] = org.projects
            print(f"    Found {len(projects)} project(s) in organization '{org.name}'.")

            for proj in projects:
                print(f"      Project: '{proj.name}' (ID: {proj.id}, Type: {proj.project_type})")
                # To access raw data, Pydantic models can be dumped: json.loads(proj.model_dump_json(indent=2))
                # print(f"        Raw project data (first 500 chars): {proj.model_dump_json(indent=2)[:500]}...")
                
                # Access issues for each project.
                issues: List[IssuePydanticModel] = proj.issues
                print(f"        Found {len(issues)} issue(s) for project '{proj.name}'.")
                if issues:
                    all_project_issues.extend(issues)
                    # print(f"          First issue ID (if any): {issues[0].id}, Title: {issues[0].title}")

        print(f"\nTotal issues collected from all projects via iteration: {len(all_project_issues)}")

    except Exception as e:
        print(f"An error occurred while fetching orgs/projects/issues: {e}")

    # --- Fetching Issues directly from the Group with parameters ---
    print("\nFetching 'code' issues (ignored=True) directly from the group...")
    try:
        # This demonstrates fetching issues at the group level with specific filters.
        # Use fetch_issues for explicit fetching with parameters.
        # The 'issues' property on GroupPydanticModel would fetch with default/no params.
        group_code_issues_params = {
            'type': "code",
            'ignored': True
        }
        group_code_issues: List[IssuePydanticModel] = group.fetch_issues(params=group_code_issues_params)
        print(f"Found {len(group_code_issues)} 'code' issues (ignored=True) in the group using fetch_issues with params.")
        if group_code_issues:
            # Accessing attributes via Pydantic model structure
            example_issue = group_code_issues[0]
            print(f"  Example issue ID: {example_issue.id}, Key Asset: {example_issue.attributes.key_asset}")

    except Exception as e:
        print(f"An error occurred while fetching group-level issues: {e}")

    # --- Fetching Assets ---
    print("\nFetching assets matching a query (e.g., 'repository' type with 'snyker' in name)...")
    # Replace with a query relevant to your Snyk assets.
    # Asset types can be 'repository', 'image', 'package', etc.
    asset_query = { # Ensure this query structure matches what get_assets_by_query expects
        # The internal structure of the query for POST /assets/search might be specific
        "query": {
            "attributes": {
                "operator": "and",
                "values": [
                    {"attribute": "type", "operator": "equal", "values": ["repository"]},
                    {"attribute": "name", "operator": "contains", "values": ["snyker"]}
                ]
            }
        }
    }
    try:
        # Use the new method name for querying assets
        assets: List[Asset] = group.get_assets_by_query(query=asset_query)
        print(f"Found {len(assets)} asset(s) matching the query.")
        if assets:
            example_asset: Asset = assets[0]
            print(f"  Example asset: '{example_asset.name}' (ID: {example_asset.id}, Type: {example_asset.type})")

            # Accessing raw data from Pydantic model
            # print(f"    Raw asset data (first 500 chars): {example_asset.model_dump_json(indent=2)[:500]}...")

            # Fetching related entities for an asset using properties
            print(f"    Fetching projects related to asset '{example_asset.name}'...")
            asset_projects: List[ProjectPydanticModel] = example_asset.projects
            print(f"      Found {len(asset_projects)} project(s) for this asset.")

            print(f"    Fetching organizations related to asset '{example_asset.name}'...")
            asset_orgs: List[OrganizationPydanticModel] = example_asset.organizations
            print(f"      Found {len(asset_orgs)} organization(s) for this asset.")

            # --- Fetching a Single Asset by ID ---
            print(f"\nFetching a single asset by its ID ('{example_asset.id}')...")
            # Use the new method name for fetching a specific asset
            specific_asset: Optional[Asset] = group.get_specific_asset(asset_id=example_asset.id)
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
    api_client.close() # Close the client instance created at the start
    print("API client closed. Script finished.")


if __name__ == "__main__":
    main()
