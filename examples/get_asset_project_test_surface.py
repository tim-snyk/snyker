import os
import logging
from snyker import GroupPydanticModel, APIClient
from snyker.config import API_CONFIG

# --- Configuration ---
# Make sure to set your SNYK_TOKEN environment variable
if not os.getenv("SNYK_TOKEN"):
    raise ValueError("SNYK_TOKEN environment variable not set.")

from snyker.config import EXAMPLES_CONFIG
# --- Snyk API Details ---
# Replace with your Group ID
TEST_GROUP_ID = EXAMPLES_CONFIG.get("group_id")
# Define asset criteria to find a specific asset
KNOWN_ASSET_NAME_CONTAINS = EXAMPLES_CONFIG.get("asset_name_contains")
KNOWN_ASSET_TYPE = EXAMPLES_CONFIG.get("asset_type")


# --- Main script ---
def main():
    """
    Fetches a specific asset from a Snyk group, retrieves its related projects,
    and prints the 'test_surface' for each project.
    """
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    api_client = APIClient(logging_level=logging.INFO)
    API_CONFIG["loading_strategy"] = "lazy"

    try:
        logging.info(f"Fetching group: {TEST_GROUP_ID}")
        group = GroupPydanticModel.get_instance(
            api_client=api_client, group_id=TEST_GROUP_ID
        )
    except ValueError as e:
        logging.error(f"Could not get group instance {TEST_GROUP_ID}: {e}")
        return

    # Query to find the asset
    asset_query = {
        "query": {
            "attributes": {
                "operator": "and",
                "values": [
                    {
                        "attribute": "type",
                        "operator": "equal",
                        "values": [KNOWN_ASSET_TYPE],
                    },
                    {
                        "attribute": "name",
                        "operator": "contains",
                        "values": [KNOWN_ASSET_NAME_CONTAINS],
                    },
                ],
            }
        }
    }

    logging.info(
        f"Searching for asset containing '{KNOWN_ASSET_NAME_CONTAINS}' of type '{KNOWN_ASSET_TYPE}'..."
    )
    # The API requires a limit of at least 10 for this endpoint
    assets = group.get_assets_by_query(query=asset_query, params={"limit": 10})

    if not assets:
        logging.warning(
            f"No asset found matching the criteria in group {TEST_GROUP_ID}."
        )
        return

    # Use the first asset found
    asset_to_inspect = assets[0]
    logging.info(f"Found asset: {asset_to_inspect.name} (ID: {asset_to_inspect.id})")

    # Lazy-load the projects related to this asset
    logging.info("Fetching related projects...")
    projects = asset_to_inspect.projects

    if not projects:
        logging.info(f"No projects found for asset {asset_to_inspect.name}.")
        return

    logging.info(
        f"Found {len(projects)} project(s) for asset '{asset_to_inspect.name}':"
    )

    # Print the test_surface for each project
    for project in projects:
        # The 'test_surface' is an attribute on the ProjectPydanticModel
        test_surface = getattr(project, "test_surface", "Not available")
        logging.info(f"  - Project: {project.name} (ID: {project.id})")
        logging.info(f"    - Test Surface: {test_surface}")

    api_client.close()


if __name__ == "__main__":
    main()
