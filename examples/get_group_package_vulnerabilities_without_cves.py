"""
examples/get_group_package_vulnerabilities_without_cves.py

This script uses the Snyk SDK (snyker) to:
- Connect to a specified Snyk Group using SNYK_TOKEN and SNYK_GROUP_ID.
- Fetch all issues of type 'package_vulnerability'.
- Identify and list package vulnerabilities that do NOT have an associated CVE identifier.

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
    Main function to fetch and identify package vulnerabilities without CVEs.
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
    api_client = APIClient(
        # Optionally configure logging_level for the SDK client itself
        # logging_level=logging.INFO # or logging.DEBUG for more verbose SDK logs
    )

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

    vulnerabilities_without_cve: List[IssuePydanticModel] = []

    try:
        logger.info(f"Fetching 'package_vulnerability' issues for Group '{group.name}'...")
        # The SDK's paginate method handles fetching all issues across pages
        # We filter by type at the API level for efficiency.
        issue_params = {'type': 'package_vulnerability', 'limit': 100}
        package_vulnerabilities: List[IssuePydanticModel] = group.fetch_issues(params=issue_params)
        
        logger.info(f"Fetched {len(package_vulnerabilities)} package vulnerabilities. Analyzing for CVEs...")

        for issue in package_vulnerabilities:
            has_cve = False
            if issue.attributes and issue.attributes.problems:
                for problem in issue.attributes.problems:
                    if problem.source and problem.source.upper() == "CVE":
                        has_cve = True
                        break # Found a CVE, no need to check other problems for this issue
            
            if not has_cve:
                vulnerabilities_without_cve.append(issue)

        if vulnerabilities_without_cve:
            print("\n--- Package Vulnerabilities WITHOUT CVEs ---")
            for issue in vulnerabilities_without_cve:
                project_info = ""
                if issue.relationships and issue.relationships.scan_item:
                    project_info = f" (Project ID: {issue.relationships.scan_item.id})"
                
                # Attempt to get project name if the project object is loaded (depends on SDK loading strategy)
                # This is a best-effort for more context in the output.
                project_name_str = ""
                if issue._project and issue._project.name: # Accessing private _project for example purposes
                    project_name_str = f", Project Name: {issue._project.name}"


                print(f"- ID: {issue.id}, Title: \"{issue.title}\"{project_info}{project_name_str}")
            logger.info(f"Found {len(vulnerabilities_without_cve)} package vulnerabilities without CVEs.")
        else:
            print("\nNo package vulnerabilities found without CVEs in this group.")
            logger.info("No package vulnerabilities found without CVEs in this group.")

    except Exception as e:
        logger.error(f"An error occurred during script execution: {e}", exc_info=True)
    finally:
        logger.info("Closing the API client...")
        api_client.close()
        logger.info("API client closed. Script finished.")

if __name__ == "__main__":
    main()
