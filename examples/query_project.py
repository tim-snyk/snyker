"""
examples/query_project.py

A simple script to query a specific Snyk project and list its issues.

This script takes a Project ID and an Organization ID as command-line arguments,
fetches the project details, and then lists all issues associated with it.

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN environment variable with a Snyk API token.
- Set the SNYK_GROUP_ID environment variable with the ID of the Snyk Group to target.

Usage:
poetry run python examples/query_project.py --project-id <PROJECT_ID> --org-id <ORG_ID>
"""

import argparse
import logging
import os
import sys
from typing import List

from snyker import (
    APIClient,
    GroupPydanticModel,
    IssuePydanticModel,
    ProjectPydanticModel,
)

# Configure basic logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """
    Main function to query a project and list its issues.
    """
    parser = argparse.ArgumentParser(
        description="Query a Snyk project and list its issues."
    )
    parser.add_argument(
        "--project-id", required=True, help="The ID of the Snyk project to query."
    )
    parser.add_argument(
        "--org-id",
        required=True,
        help="The ID of the Snyk organization the project belongs to.",
    )
    args = parser.parse_args()

    project_id = args.project_id
    org_id = args.org_id
    snyk_group_id = os.getenv("SNYK_GROUP_ID", "9365faba-3e72-4fda-9974-267779137aa6")

    logger.info("Initializing Snyk API Client and Group...")
    api_client = APIClient()
    group = GroupPydanticModel.get_instance(
        api_client=api_client, group_id=snyk_group_id
    )

    try:
        logger.info(f"Fetching organization: {org_id}")
        organization = group.get_organization_by_id(org_id)
        if not organization:
            logger.error(
                f"Could not find organization with ID: {org_id} in group {group.name}"
            )
            sys.exit(1)

        logger.info(f"Fetching project: {project_id}")
        project = organization.get_specific_project(project_id)
        if not project:
            logger.error(
                f"Could not find project with ID: {project_id} in organization {organization.name}"
            )
            sys.exit(1)

        print(f"\n--- Project Details ---")
        print(f"  Name: {project.name}")
        print(f"  ID: {project.id}")
        print(f"  Status: {project.status}")
        print(f"  Origin: {project.origin}")
        print(f"  Type: {project.project_type}")
        print(f"-----------------------")

        logger.info(f"Fetching issues for project: {project.name}")
        issues = project.fetch_issues()

        if not issues:
            print(f"\nNo issues found for project '{project.name}'.")
            return

        print(f"\n--- Found {len(issues)} Issues for Project: {project.name} ---")
        for issue in issues:
            attrs = issue.attributes
            print(f"\n-----------------------------------------")
            print(f"  Title: {attrs.title}")
            print(f"  Issue ID: {issue.id}")
            print(
                f"  Severity: {attrs.effective_severity_level.capitalize() if attrs.effective_severity_level else 'N/A'}"
            )
            print(f"  Type: {attrs.type}")

            # Focus on timestamp fields
            print("\n  --- Timestamps ---")
            print(
                f"    Issue Created At: {attrs.created_at.isoformat() if attrs.created_at else 'N/A'}"
            )
            print(
                f"    Issue Updated At: {attrs.updated_at.isoformat() if attrs.updated_at else 'N/A'}"
            )
            print(
                f"    Issue Resolved At: {attrs.resolved_at.isoformat() if attrs.resolved_at else 'N/A'}"
            )

            if attrs.problems:
                for problem in attrs.problems:
                    print(f"    Problem ({problem.source} - {problem.id}):")
                    print(
                        f"      - Updated At: {problem.updated_at.isoformat() if problem.updated_at else 'N/A'}"
                    )
                    print(
                        f"      - Disclosed At: {problem.disclosed_at.isoformat() if problem.disclosed_at else 'N/A'}"
                    )
                    print(
                        f"      - Discovered At: {problem.discovered_at.isoformat() if problem.discovered_at else 'N/A'}"
                    )

            if attrs.severities:
                for severity in attrs.severities:
                    print(f"    Severity ({severity.source} - {severity.level}):")
                    print(
                        f"      - Modification Time: {severity.modification_time.isoformat() if severity.modification_time else 'N/A'}"
                    )

            print(f"-----------------------------------------")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Closing API client.")
        api_client.close()


if __name__ == "__main__":
    main()
