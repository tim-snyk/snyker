"""
examples/find_issues_by_purl.py

A script to find issues for a specific package version using a Package URL (purl).

This script takes a PURL as a command-line argument, constructs a PackageURL object,
and then uses the SDK to fetch and list all issues for that package in a given
organization.

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN environment variable with a Snyk API token.
- Set the SNYK_GROUP_ID and SNYK_ORG_ID environment variables.

Usage:
poetry run python examples/find_issues_by_purl.py <PURL>
"""
import argparse
import logging
import os
import sys

from snyker import APIClient, GroupPydanticModel
from snyker.purl import PackageURL

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """
    Main function to find issues for a purl.
    """
    parser = argparse.ArgumentParser(description="Find issues for a specific package version using a PURL.")
    parser.add_argument("purl", help="The Package URL (purl) of the package to query.")
    args = parser.parse_args()

    purl_str = args.purl
    snyk_group_id = os.getenv("SNYK_GROUP_ID")
    snyk_org_id = os.getenv("SNYK_ORG_ID")

    if not snyk_group_id or not snyk_org_id:
        logger.error("SNYK_GROUP_ID and SNYK_ORG_ID environment variables must be set.")
        sys.exit(1)

    # A simple parser for the purl string.
    # This is not a complete purl parser, but it works for this example.
    try:
        purl_parts = purl_str.split('/')
        purl_type = purl_parts[0].replace('pkg:', '')
        purl_name = purl_parts[-1].split('@')[0]
        purl_version = purl_parts[-1].split('@')[1]
        purl_namespace = "/".join(purl_parts[1:-1]) if len(purl_parts) > 2 else None
    except IndexError:
        logger.error(f"Could not parse purl: {purl_str}")
        sys.exit(1)

    purl = PackageURL(
        type=purl_type,
        namespace=purl_namespace,
        name=purl_name,
        version=purl_version,
    )

    logger.info("Initializing Snyk API Client and Group...")
    api_client = APIClient()
    group = GroupPydanticModel.get_instance(api_client=api_client, group_id=snyk_group_id)

    try:
        logger.info(f"Fetching organization: {snyk_org_id}")
        organization = group.get_organization_by_id(snyk_org_id)
        if not organization:
            logger.error(f"Could not find organization with ID: {snyk_org_id} in group {group.name}")
            sys.exit(1)

        logger.info(f"Fetching issues for purl: {purl.to_string()}")
        issues = organization.fetch_issues_for_purl(purl)

        if not issues:
            print(f"\nNo issues found for purl '{purl_str}'.")
            return

        print(f"\n--- Found {len(issues)} Issues for PURL: {purl_str} ---")
        for issue in issues:
            attrs = issue.attributes
            print(f"\n-----------------------------------------")
            print(f"  Title: {attrs.title}")
            print(f"  Issue ID: {issue.id}")
            print(f"  Severity: {attrs.effective_severity_level.capitalize() if attrs.effective_severity_level else 'N/A'}")
            print(f"  Type: {attrs.type}")
            print(f"  Created Time: {attrs.created_at.isoformat() if attrs.created_at else 'N/A'}")
            print(f"-----------------------------------------")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Closing API client.")
        api_client.close()

if __name__ == "__main__":
    main()
