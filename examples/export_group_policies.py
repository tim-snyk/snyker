import argparse
import csv
import logging
import os
import json
from datetime import datetime
from typing import Optional # Added Optional for type hinting

from snyker.api_client import APIClient
from snyker.group import GroupPydanticModel
from snyker.organization import OrganizationPydanticModel
from snyker.policy import PolicyPydanticModel
from snyker.project import ProjectPydanticModel

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def format_datetime_for_csv(dt_obj: Optional[datetime]) -> str:
    """Formats a datetime object to an ISO string, or returns empty string if None."""
    return dt_obj.isoformat() if dt_obj else ""

def export_group_policies_to_csv(api_client: APIClient, group_id: Optional[str] = None):
    """
    Exports all policies from all organizations within a Snyk Group to a CSV file.
    """
    try:
        logger.info(f"Attempting to get group instance for group_id: {group_id if group_id else 'auto-discover'}")
        group = GroupPydanticModel.get_instance(api_client=api_client, group_id=group_id)
        logger.info(f"Successfully retrieved group: {group.name} (ID: {group.id})")

        all_policies_data = []
        
        logger.info(f"Fetching organizations for group '{group.name}'...")
        organizations = group.organizations # This will trigger fetch_organizations if not already loaded
        if not organizations:
            logger.warning(f"No organizations found for group '{group.name}'.")
            return

        logger.info(f"Found {len(organizations)} organizations in group '{group.name}'.")

        for org in organizations:
            logger.info(f"Fetching policies for organization: {org.name} (ID: {org.id})...")
            try:
                # Ensure policies are fetched. The property access should trigger fetch_policies if lazy.
                # If eager loading is on, they might already be there.
                # Explicitly calling fetch_policies() ensures they are fetched if not.
                org_policies = org.fetch_policies() 
                if not org_policies:
                    logger.info(f"No policies found for organization {org.name}.")
                    continue
                
                logger.info(f"Found {len(org_policies)} policies in organization {org.name}.")
                for policy in org_policies:
                    conditions_group_json = ""
                    if policy.conditions_group:
                        try:
                            # Attempt to convert Pydantic model to dict for JSON serialization
                            conditions_group_dict = policy.conditions_group.model_dump(mode='json')
                            conditions_group_json = json.dumps(conditions_group_dict)
                        except Exception as e:
                            logger.error(f"Error serializing conditions_group for policy {policy.id}: {e}")
                            conditions_group_json = "{'error': 'serialization_failed'}"

                    policy_row = {
                        "organization_id": org.id,
                        "organization_name": org.name,
                        "policy_id": policy.id,
                        "policy_name": policy.name or "",
                        "policy_created_at": format_datetime_for_csv(policy.created_at),
                        "policy_updated_at": format_datetime_for_csv(policy.updated_at),
                        "policy_action_type": policy.action_type or "",
                        "policy_ignore_type": policy.ignore_type or "",
                        "policy_expires": format_datetime_for_csv(policy.expires),
                        "policy_reason": policy.reason or "",
                        "policy_created_by_name": policy.created_by_name or "",
                        "policy_conditions_group_json": conditions_group_json,
                    }
                    all_policies_data.append(policy_row)
            except Exception as e_org_policies:
                logger.error(f"Error fetching policies for organization {org.name}: {e_org_policies}", exc_info=True)
                continue # Continue to the next organization

        if not all_policies_data:
            logger.info("No policies found across all organizations in the group.")
            return

        # Fetch v1 ignores for each project
        for org in organizations:
            logger.info(f"Fetching projects for organization: {org.name} (ID: {org.id}) to check for v1 ignores...")
            # We need to implement fetch_projects in the Organization model first.
            # For now, let's assume it exists and fetches projects.
            projects = org.projects # This should trigger a fetch if lazy
            logger.info(f"Found {len(projects)} projects in {org.name}. Now fetching v1 ignores for each.")
            for project in projects:
                try:
                    v1_ignores = project.get_ignores_v1()
                    if not v1_ignores:
                        continue
                    
                    logger.info(f"Found {len(v1_ignores)} v1 ignores for project {project.name} ({project.id}).")
                    for ignore_item in v1_ignores:
                        # v1 ignores are structured as a dictionary where the key is the issue ID
                        for issue_id, ignores in ignore_item.items():
                            for ignore_rule in ignores:
                                # The details are nested under a '*' key
                                ignore_details = ignore_rule.get('*', {})
                                policy_row = {
                                    "organization_id": org.id,
                                    "organization_name": org.name,
                                    "policy_id": f"v1-ignore-{project.id}-{issue_id}",
                                    "policy_name": f"Ignore for {issue_id} in {project.name}",
                                    "policy_created_at": "",
                                    "policy_updated_at": "",
                                    "policy_action_type": "ignore",
                                    "policy_ignore_type": ignore_details.get('reasonType', 'Unknown'),
                                    "policy_expires": ignore_details.get('expires', ''),
                                    "policy_reason": ignore_details.get('reason', 'No reason provided'),
                                    "policy_created_by_name": ignore_details.get('ignoredBy', {}).get('name', 'Unknown'),
                                    "policy_conditions_group_json": json.dumps({"v1_ignore_path": ignore_rule.get('path', '*')}),
                                }
                                all_policies_data.append(policy_row)
                except Exception as e_v1_ignore:
                    logger.error(f"Error fetching v1 ignores for project {project.name}: {e_v1_ignore}", exc_info=True)
                    continue

        if not all_policies_data:
            logger.info("No policies or v1 ignores found across all organizations in the group.")
            return

        # Generate CSV filename
        group_name_slug = group.name.lower().replace(' ', '_').replace('/', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"group_policies_and_ignores_{group_name_slug}_{timestamp}.csv"
        
        csv_fieldnames = [
            "organization_id", "organization_name", "policy_id", "policy_name",
            "policy_created_at", "policy_updated_at", "policy_action_type",
            "policy_ignore_type", "policy_expires", "policy_reason",
            "policy_created_by_name", "policy_conditions_group_json"
        ]

        logger.info(f"Writing {len(all_policies_data)} policies and ignores to CSV file: {csv_filename}")
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
            writer.writeheader()
            writer.writerows(all_policies_data)
        
        logger.info(f"Successfully exported policies to {csv_filename}")

    except ValueError as ve:
        logger.error(f"Configuration or Group/Org data error: {ve}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Snyk Group policies to a CSV file.")
    parser.add_argument(
        "--snyk-token",
        type=str,
        default=os.environ.get("SNYK_TOKEN"),
        help="Snyk API token. Can also be set via SNYK_TOKEN environment variable.",
    )
    parser.add_argument(
        "--group-id",
        type=str,
        default=os.environ.get("SNYK_GROUP_ID"),
        help="Snyk Group ID. If not provided, the script will attempt to auto-discover if only one group is accessible. Can also be set via SNYK_GROUP_ID environment variable.",
    )
    
    args = parser.parse_args()

    if not args.snyk_token:
        logger.error("Snyk token is required. Please provide it via --snyk-token argument or SNYK_TOKEN environment variable.")
    else:
        # The APIClient constructor in snyker/api_client.py reads the token from SNYK_TOKEN env var
        # or expects it to be set if SNYK_TOKEN is not available.
        # It does not accept a 'token' argument directly in the constructor.
        # We ensure SNYK_TOKEN is set if args.snyk_token is provided.
        if args.snyk_token:
            os.environ['SNYK_TOKEN'] = args.snyk_token
        
        client = APIClient() # Constructor will use SNYK_TOKEN from env
        export_group_policies_to_csv(api_client=client, group_id=args.group_id)
