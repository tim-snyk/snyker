"""
examples/find_issue_by_attribute_value.py

This script uses the Snyk SDK (snyker) to:
- Connect to a specified Snyk Group using SNYK_TOKEN and SNYK_GROUP_ID.
- Accept a search value as a command-line argument.
- Fetch all issues for the group.
- Recursively search within each issue's data for the provided attribute value.
- Print details of the first issue found containing the value and the path to that value.

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN environment variable with a Snyk API token.
- Set the SNYK_GROUP_ID environment variable with the ID of the Snyk Group to target.

Usage:
poetry run python examples/find_issue_by_attribute_value.py <search_value>
Example:
poetry run python examples/find_issue_by_attribute_value.py "f32c44dc-b1a6-46de-9a32-ba93acf001f7"
"""
from snyker import GroupPydanticModel, APIClient, IssuePydanticModel
from typing import List, Dict, Any, Optional, Tuple
import os
import logging
import argparse
import json

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def recursive_find_value_path(data_structure: Any, search_value: str, current_path: str = "") -> Optional[str]:
    """
    Recursively searches for search_value in a nested data structure (dicts and lists).
    Returns the path to the first occurrence of the value.
    """
    if isinstance(data_structure, dict):
        for key, value in data_structure.items():
            new_path = f"{current_path}.{key}" if current_path else key
            if isinstance(value, str) and value == search_value:
                return new_path
            if isinstance(value, (dict, list)):
                found_path = recursive_find_value_path(value, search_value, new_path)
                if found_path:
                    return found_path
    elif isinstance(data_structure, list):
        for index, item in enumerate(data_structure):
            new_path = f"{current_path}[{index}]"
            if isinstance(item, str) and item == search_value:
                return new_path
            if isinstance(item, (dict, list)):
                found_path = recursive_find_value_path(item, search_value, new_path)
                if found_path:
                    return found_path
    return None

def main():
    """
    Main function to find an issue by a specific attribute value.
    """
    parser = argparse.ArgumentParser(description="Find a Snyk issue by a specific attribute value within a group.")
    parser.add_argument("search_value", type=str, help="The attribute value to search for within issues.")
    args = parser.parse_args()
    search_value = args.search_value

    snyk_token = os.getenv("SNYK_TOKEN")
    snyk_group_id = os.getenv("SNYK_GROUP_ID")

    if not snyk_token:
        logger.error("Error: SNYK_TOKEN environment variable not set.")
        print("Please set SNYK_TOKEN with your Snyk API token.")
        return

    if not snyk_group_id:
        logger.error("Error: SNYK_GROUP_ID environment variable not set.")
        print("Please set SNYK_GROUP_ID with the ID of the Snyk Group to target.")
        return

    logger.info(f"Initializing Snyk APIClient. Searching for value: \"{search_value}\"")
    api_client = APIClient()

    try:
        logger.info(f"Attempting to initialize Group: {snyk_group_id}")
        group = GroupPydanticModel.get_instance(api_client=api_client, group_id=snyk_group_id)
        logger.info(f"Successfully initialized Group: '{group.name}' (ID: {group.id})")
    except ValueError as e:
        logger.error(f"Error initializing Group (ID: {snyk_group_id}): {e}")
        api_client.close()
        return
    except Exception as e:
        logger.error(f"An unexpected error occurred during Group initialization: {e}", exc_info=True)
        api_client.close()
        return

    found_issues_list: List[Tuple[IssuePydanticModel, str]] = [] # Changed to a list

    try:
        logger.info(f"Fetching all issues for Group '{group.name}' to search for value '{search_value}'...")
        # Fetch all types of issues, limit 100 per page is default in SDK's paginate
        all_issues: List[IssuePydanticModel] = group.fetch_issues(params={'limit': 100})
        
        logger.info(f"Fetched {len(all_issues)} issues. Analyzing...")

        for issue in all_issues:
            # Convert Pydantic model to dict for easier recursive search.
            # mode='json' ensures complex types like datetime are serialized to strings.
            issue_dict = issue.model_dump(mode='json') 
            
            path_to_value = recursive_find_value_path(issue_dict, search_value)
            
            if path_to_value:
                found_issues_list.append((issue, path_to_value))
                # Removed break to find all occurrences

        if found_issues_list:
            print(f"\n--- Found {len(found_issues_list)} Issue(s) Containing Value: \"{search_value}\" ---")
            for idx, (issue_obj, path) in enumerate(found_issues_list):
                print(f"\nMatch {idx + 1}:")
                print(f"  Issue ID: {issue_obj.id}")
                print(f"  Issue Title: \"{issue_obj.title}\"")
                print(f"  Issue Type: {issue_obj.attributes.type if issue_obj.attributes else 'N/A'}")
                print(f"  Path to value: {path}")
                
                project_info = "N/A"
                if issue_obj.relationships and issue_obj.relationships.scan_item and issue_obj.relationships.scan_item.id:
                    project_info = f"ID: {issue_obj.relationships.scan_item.id}, Type: {issue_obj.relationships.scan_item.type}"
                print(f"  Associated Scan Item: {project_info}")
                logger.info(f"Match {idx + 1}: Found value '{search_value}' in Issue ID {issue_obj.id} at path '{path}'.")
        else:
            print(f"\nValue \"{search_value}\" not found in any issue within Group '{group.name}'.")
            logger.info(f"Value \"{search_value}\" not found in any of the {len(all_issues)} issues checked.")

    except Exception as e:
        logger.error(f"An error occurred during script execution: {e}", exc_info=True)
    finally:
        logger.info("Closing the API client...")
        api_client.close()
        logger.info("API client closed. Script finished.")

if __name__ == "__main__":
    main()
