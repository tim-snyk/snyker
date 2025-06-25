from __future__ import annotations
from typing import List, Dict, Optional, Any, Tuple, TYPE_CHECKING
from datetime import datetime
import logging

from pydantic import (
    BaseModel,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
    ConfigDict,
)

from snyker.utils import datetime_converter
from .api_client import APIClient

# from .organization import OrganizationPydanticModel # Moved to TYPE_CHECKING

if TYPE_CHECKING:
    from .organization import OrganizationPydanticModel


class PolicyCondition(BaseModel):
    """Represents a single condition within a Snyk policy."""

    field: Optional[str] = None
    operator: Optional[str] = None
    value: Optional[Any] = None


class PolicyConditionsGroup(BaseModel):
    """Represents a group of conditions in a Snyk policy, combined by a logical operator."""

    logical_operator: Optional[str] = Field(default=None, alias="logicalOperator")
    conditions: List[PolicyCondition] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def adapt_single_condition_to_list(cls, data: Any) -> Any:
        """Adapts API response to ensure 'conditions' is always a list.

        Snyk API might return a single condition dictionary or a list of them.
        This validator also handles an older, flatter structure for backward
        compatibility during parsing, converting it to the new list structure.

        Args:
            data: The input data for validation.

        Returns:
            The (potentially) transformed data.
        """
        if isinstance(data, dict):
            if "conditions" in data and isinstance(data["conditions"], dict):
                data["conditions"] = [data["conditions"]]
            elif (
                "field" in data and "operator" in data and "value" in data
            ):  # Legacy handling
                condition_dict = {
                    "field": data.pop("field"),
                    "operator": data.pop("operator"),
                    "value": data.pop("value"),
                }
                if "conditions" in data and isinstance(data["conditions"], list):
                    data["conditions"].append(condition_dict)
                else:
                    data["conditions"] = [condition_dict]
        return data


class PolicyActionData(BaseModel):
    """Data associated with a policy action, such as ignore details."""

    ignore_type: Optional[str] = Field(default=None, alias="ignoreType")
    expires: Optional[Any] = None
    reason: Optional[str] = None

    @field_validator("expires", mode="before")
    @classmethod
    def convert_expires_datetime(cls, value: Any) -> Optional[Any]:
        """Converts 'expires' field to a datetime object."""
        if value:
            return datetime_converter(value)
        return None


class PolicyAction(BaseModel):
    """Represents the action taken by a policy."""

    data: Optional[PolicyActionData] = None


class PolicyCreatedBy(BaseModel):
    """Information about the user who created the policy."""

    name: Optional[str] = None
    email: Optional[str] = None
    id: Optional[str] = None


class PolicyAttributes(BaseModel):
    """Core attributes of a Snyk policy."""

    name: Optional[str] = None
    review: Optional[Any] = None
    created_at: Optional[Any] = Field(default=None, alias="createdAt")
    updated_at: Optional[Any] = Field(default=None, alias="updatedAt")
    conditions_group: Optional[PolicyConditionsGroup] = Field(
        default=None, alias="conditionsGroup"
    )
    action_type: Optional[str] = Field(default=None, alias="actionType")
    action: Optional[PolicyAction] = None
    created_by: Optional[PolicyCreatedBy] = Field(default=None, alias="createdBy")

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def convert_datetimes(cls, value: Any) -> Optional[Any]:
        """Converts string datetime fields to datetime objects."""
        if value:
            return datetime_converter(value)
        return None


class PolicyPydanticModel(BaseModel):
    """Represents a Snyk security policy.

    Attributes:
        id: The unique identifier of the policy.
        type: The type of the Snyk entity (should be "policy").
        attributes: Detailed attributes of the policy.
    """

    id: str
    type: str
    attributes: PolicyAttributes

    _api_client: APIClient = PrivateAttr()
    _organization: OrganizationPydanticModel = PrivateAttr()
    _logger: logging.Logger = PrivateAttr()

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @classmethod
    def from_api_response(
        cls,
        policy_data: Dict[str, Any],
        api_client: APIClient,
        organization: OrganizationPydanticModel,
    ) -> PolicyPydanticModel:
        """Creates a PolicyPydanticModel instance from API response data.

        Args:
            policy_data: The 'data' part of an API item representing a policy.
            api_client: An instance of the APIClient.
            organization: The parent OrganizationPydanticModel instance.

        Returns:
            An initialized PolicyPydanticModel instance.
        """
        instance = cls(**policy_data)
        instance._api_client = api_client
        instance._organization = organization
        instance._logger = api_client.logger

        instance._logger.debug(
            f"[Policy ID: {instance.id}] Created policy object for '{instance.name}'"
        )
        return instance

    @property
    def name(self) -> Optional[str]:
        """The name of the policy."""
        return self.attributes.name

    @property
    def created_at(self) -> Optional[datetime]:
        """The creation timestamp of the policy."""
        return (
            self.attributes.created_at
            if isinstance(self.attributes.created_at, datetime)
            else None
        )

    @property
    def updated_at(self) -> Optional[datetime]:
        """The last update timestamp of the policy."""
        return (
            self.attributes.updated_at
            if isinstance(self.attributes.updated_at, datetime)
            else None
        )

    @property
    def conditions_group(self) -> Optional[PolicyConditionsGroup]:
        """The group of conditions that define when this policy applies."""
        return self.attributes.conditions_group

    @property
    def action_type(self) -> Optional[str]:
        """The type of action this policy performs (e.g., 'ignore')."""
        return self.attributes.action_type

    @property
    def ignore_type(self) -> Optional[str]:
        """If the action is 'ignore', this specifies the type of ignore (e.g., 'not-vulnerable')."""
        if self.attributes.action and self.attributes.action.data:
            return self.attributes.action.data.ignore_type
        return None

    @property
    def expires(self) -> Optional[datetime]:
        """If the action is 'ignore', this is the expiration date of the ignore."""
        if (
            self.attributes.action
            and self.attributes.action.data
            and isinstance(self.attributes.action.data.expires, datetime)
        ):
            return self.attributes.action.data.expires
        return None

    @property
    def reason(self) -> Optional[str]:
        """The reason provided for this policy action (e.g., reason for an ignore)."""
        if self.attributes.action and self.attributes.action.data:
            return self.attributes.action.data.reason
        return None

    @property
    def created_by_name(self) -> Optional[str]:
        """The name of the user who created this policy."""
        if self.attributes.created_by:
            return self.attributes.created_by.name
        return None
