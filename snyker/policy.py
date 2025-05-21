from __future__ import annotations
from typing import TYPE_CHECKING, List, Dict, Optional, Tuple
from snyker import datetime_converter
if TYPE_CHECKING:
    from snyker import Organization


class Policy:
    """
    Policy class to handle policies in Snyk and provide a consistent interface for accessing policy data.
    """
    def __init__(self,
                 org: 'Organization',
                 policy_data: dict,
                 ):
        try:
            self.org = org
            self.api_client = org.group.api_client
            self.logger = self.api_client.logger
            self.raw = policy_data
            self.id = policy_data.get('id')
            self.type = policy_data.get('type')  # Allowed: policy

            attributes = policy_data.get('attributes', {})
            self.name = attributes.get('name')
            self.review = attributes.get('review')
            self.created_at = datetime_converter(attributes.get('created_at', str))
            self.conditions_group = self.ConditionsGroup(attributes.get('conditions_group', {}))

            # actions
            self.action_type = attributes.get('action_type')
            action_data = attributes.get('action').get('data')
            self.ignore_type = action_data.get('ignore_type')
            if self.ignore_type == 'temporary-ignore' and action_data.get('expires'):
                self.expires = datetime_converter(action_data.get('expires'))
            self.reason = action_data.get('reason', '')
            # created_by
            created_by = attributes.get('created_by')
            self.created_by_name = created_by.get('name')
            self.created_at_email = created_by.get('email')
            self.created_by_id = created_by.get('id')
            self.updated_at = datetime_converter(attributes.get('updated_at', str))

        except KeyError as e:
            self.api_client.logger.error(f"KeyError: {e} in policy data: {policy_data}")
            raise
        except Exception as e:
            self.api_client.logger.error(f"Unexpected error: {e} in policy data: {policy_data}")
            raise

        self.logger.debug(f"[Policy ID: {self.id}].__init__ created policy object for {self.name}")

    class ConditionsGroup:
        """
        ConditionsGroup inner class to handle conditions in policies which is the only location this class has meaning.
        in the '2024-10-15' endpoint, it is only provided as very narrow set of use cases.
        """

        def __init__(self, conditions_group):
            self.logical_operator = conditions_group['logical_operator']  # Allowed: 'and'
            self.conditions = List[Tuple[str, str, str]]
            condition = conditions_group['conditions'][0]  # Min:1, Max: 1
            self.field = condition.get('field')  # Allowed: 'snyk/asset/finding/v1'
            self.operator = condition.get('operator')  # Allowed: 'includes'
            self.value = condition.get('value')  # Allowed: 'and'


