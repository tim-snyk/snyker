"""
examples/export_sast_sqli_issues.py

This script uses the Snyk SDK (snyker) to:
- Connect to a specified Snyk Group using SNYK_TOKEN and SNYK_GROUP_ID.
- Fetch all issues of type 'code' (SAST issues).
- Filter these issues to identify SQL Injection vulnerabilities (CWE-89).
- Export a list of these specific SQLi issues.

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN environment variable with a Snyk API token.
- Set the SNYK_GROUP_ID environment variable with the ID of the Snyk Group to target.
"""
from snyker import GroupPydanticModel, APIClient, IssuePydanticModel
from typing import List
import os
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """
    Main function to fetch and identify SAST SQLi (CWE-89) issues.
    """
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

    logger.info("Initializing Snyk APIClient...")
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

    sast_sqli_issues: List[IssuePydanticModel] = []

    try:
        logger.info(f"Fetching 'code' (SAST) issues for Group '{group.name}'...")
        # The SDK's paginate method handles fetching all issues across pages.
        # We filter by type 'code' at the API level.
        issue_params = {'type': 'code', 'limit': 100}
        sast_issues: List[IssuePydanticModel] = group.fetch_issues(params=issue_params)
        
        logger.info(f"Fetched {len(sast_issues)} SAST issues. Analyzing for CWE-89 (SQL Injection)...")

        for issue in sast_issues:
            is_sqli = False
            if issue.attributes and issue.attributes.classes:
                for issue_class in issue.attributes.classes:
                    # Check if the class ID is CWE-89 and optionally if the source is CWE
                    if issue_class.id == "CWE-89":
                        # Could also check `issue_class.source == "CWE"` for more robustness
                        is_sqli = True
                        break # Found CWE-89, no need to check other classes for this issue
            
            if is_sqli:
                sast_sqli_issues.append(issue)

        if sast_sqli_issues:
            print("\n--- SAST SQL Injection (CWE-89) Issues ---")
            for issue in sast_sqli_issues:
                project_info = ""
                project_name_str = ""
                if issue.relationships and issue.relationships.scan_item and issue.relationships.scan_item.id:
                    project_info = f" (Project ID: {issue.relationships.scan_item.id})"
                    # Attempt to get project name if the project object is loaded
                    # This depends on the SDK's loading strategy or if project details were fetched elsewhere.
                    # For this example, we'll try to access it if available.
                    if issue._project and issue._project.name: # Accessing private _project
                        project_name_str = f", Project Name: {issue._project.name}"
                    elif issue._project: # If project object exists but name is None
                         project_name_str = f", Project Name: [Name not available]"


                print(f"- ID: {issue.id}, Title: \"{issue.title}\"{project_info}{project_name_str}")
            logger.info(f"Found {len(sast_sqli_issues)} SAST SQL Injection (CWE-89) issues.")
        else:
            print("\nNo SAST SQL Injection (CWE-89) issues found in this group for the fetched 'code' type issues.")
            logger.info("No SAST SQL Injection (CWE-89) issues found.")

    except Exception as e:
        logger.error(f"An error occurred during script execution: {e}", exc_info=True)
    finally:
        logger.info("Closing the API client...")
        api_client.close()
        logger.info("API client closed. Script finished.")

if __name__ == "__main__":
    main()
