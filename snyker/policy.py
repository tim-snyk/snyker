from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Tuple, Any
from .utils import datetime_converter
from datetime import datetime
import logging

if TYPE_CHECKING:
    from .organization import Organization
    from .api_client import APIClient

class Policy:
    """
    Policy class to handle policies in Snyk and provide a consistent interface
    for accessing policy data. Policies define rules and actions for issues
    found by Snyk.

    Attributes:
        id (str): The unique identifier of the policy.
        type (str): The type of the policy resource (usually 'policy').
        name (str): The human-readable name of the policy.
        raw (Dict[str, Any]): The raw JSON data for the policy from the Snyk API.
        org (Organization): The Snyk Organization this policy belongs to.
        api_client (APIClient): The API client instance for Snyk API interactions.
        logger (logging.Logger): Logger instance for this policy.
        created_at (Optional[datetime]): Timestamp of when the policy was created.
        updated_at (Optional[datetime]): Timestamp of when the policy was last updated.
        conditions_group (Policy.ConditionsGroup): The group of conditions for this policy.
        action_type (Optional[str]): The type of action this policy performs (e.g., 'ignore').
    """
    def __init__(self,
                 org: 'Organization',
                 policy_data: Dict[str, Any],
                 ):
        """
        Initializes a Policy object.

        Args:
            org (Organization): The Snyk Organization this policy belongs to.
                                It's used to derive API client and logging context.
            policy_data (Dict[str, Any]): Raw dictionary data for the policy from the Snyk API.

        Raises:
            ValueError: If an APIClient context cannot be established via the `org` object.
            KeyError: If essential keys are missing from `policy_data`.
        """
        try:
            self.org: 'Organization' = org
            
            temp_api_client: Optional['APIClient'] = None
            if org.group and hasattr(org.group, 'api_client') and org.group.api_client:
                temp_api_client = org.group.api_client
            elif hasattr(org, 'api_client') and org.api_client:
                temp_api_client = org.api_client
            
            if temp_api_client:
                self.api_client: 'APIClient' = temp_api_client
                if hasattr(self.api_client, 'logger') and self.api_client.logger:
                    self.logger: logging.Logger = self.api_client.logger
                else:
                    self.logger = logging.getLogger(f"{__name__}.PolicyInstance.{policy_data.get('id','UnknownID')}")
                    self.logger.warning(f"Policy for org {org.id}: APIClient found but has no logger. Policy created its own.")
            else:
                provisional_logger = logging.getLogger(f"{__name__}.PolicyInitError")
                policy_id_for_log = policy_data.get('id', 'UnknownID')
                org_id_for_log = getattr(org, 'id', 'UnknownOrgID')
                provisional_logger.error(f"Policy (ID: {policy_id_for_log}) for org (ID: {org_id_for_log}) could not determine APIClient from org or org.group.")
                raise ValueError(f"Policy for org {org_id_for_log} requires an APIClient context which could not be found.")

            self.raw: Dict[str, Any] = policy_data
            self.id: Optional[str] = policy_data.get('id')
            self.type: Optional[str] = policy_data.get('type')

            attributes = policy_data.get('attributes', {})
            self.name: Optional[str] = attributes.get('name')
            self.review: Optional[Any] = attributes.get('review')
            
            created_at_str = attributes.get('created_at')
            self.created_at: Optional[datetime] = datetime_converter(created_at_str) if created_at_str else None
            
            updated_at_str = attributes.get('updated_at')
            self.updated_at: Optional[datetime] = datetime_converter(updated_at_str) if updated_at_str else None

            conditions_group_data = attributes.get('conditions_group', {})
            self.conditions_group: Policy.ConditionsGroup = self.ConditionsGroup(conditions_group_data)

            self.action_type: Optional[str] = attributes.get('action_type')
            action_details = attributes.get('action', {}).get('data', {})
            self.ignore_type: Optional[str] = action_details.get('ignore_type')
            self.expires: Optional[datetime] = None
            if self.ignore_type == 'temporary-ignore':
                expires_str = action_details.get('expires')
                if expires_str:
                    self.expires = datetime_converter(expires_str)
            self.reason: str = action_details.get('reason', '')
            
            created_by_data = attributes.get('created_by', {})
            self.created_by_name: Optional[str] = created_by_data.get('name')
            self.created_by_email: Optional[str] = created_by_data.get('email')
            self.created_by_id: Optional[str] = created_by_data.get('id')

        except KeyError as e:
            logger_to_use = getattr(self, 'logger', logging.getLogger(__name__))
            logger_to_use.error(f"KeyError initializing Policy: {e}. Policy data: {policy_data}", exc_info=True)
            raise
        except Exception as e:
            logger_to_use = getattr(self, 'logger', logging.getLogger(__name__))
            logger_to_use.error(f"Unexpected error initializing Policy: {e}. Policy data: {policy_data}", exc_info=True)
            raise

        self.logger.debug(f"[Policy ID: {self.id}] Created policy object for '{self.name}'")

    class ConditionsGroup:
        """
        Represents the group of conditions that define when a Snyk policy applies.
        In some Snyk API versions/endpoints, this might be limited in complexity
        (e.g., only a single condition).

        Attributes:
            logical_operator (Optional[str]): The logical operator combining conditions
                                             (e.g., 'and', 'or').
            conditions (List[Tuple[str, str, str]]): A list of conditions, where each
                                                     condition is a tuple, typically
                                                     (field, operator, value).
                                                     Currently, this list is initialized empty
                                                     as specific fields (field, operator, value)
                                                     are parsed from the first condition directly.
            field (Optional[str]): The field the condition applies to (e.g., 'snyk/asset/finding/v1').
            operator (Optional[str]): The operator for the condition (e.g., 'includes').
            value (Optional[Any]): The value to check against.
        """
        def __init__(self, conditions_group_data: Dict[str, Any]):
            """
            Initializes a ConditionsGroup object.

            Args:
                conditions_group_data (Dict[str, Any]): Raw dictionary data for the
                                                        conditions group from the Snyk API.
            """
            self.logical_operator: Optional[str] = conditions_group_data.get('logical_operator')
            self.conditions: List[Tuple[str, str, str]] = []

            conditions_list = conditions_group_data.get('conditions', [])
            if conditions_list and isinstance(conditions_list, list) and len(conditions_list) > 0:
                condition_data = conditions_list[0]
                if isinstance(condition_data, dict):
                    self.field: Optional[str] = condition_data.get('field')
                    self.operator: Optional[str] = condition_data.get('operator')
                    self.value: Optional[Any] = condition_data.get('value')
                else:
                    self.field = None
                    self.operator = None
                    self.value = None
            else:
                self.field = None
                self.operator = None
                self.value = None
