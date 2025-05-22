from datetime import datetime, timezone
from typing import Any


def search_json(json_obj: Any, search_string: str) -> bool:
    """Recursively searches for a string within a JSON-like object.

    Checks both keys (if a dictionary) and string values for the presence
    of `search_string`.

    Args:
        json_obj: The JSON-like object (dict, list, or string) to search.
        search_string: The string to search for.

    Returns:
        True if the string is found, False otherwise.
    """
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            if isinstance(key, str) and search_string in key: # Check keys
                return True
            if search_json(value, search_string): # Recurse on values
                return True
    elif isinstance(json_obj, list):
        for item in json_obj:
            if search_json(item, search_string): # Recurse on list items
                return True
    elif isinstance(json_obj, str):
        if search_string in json_obj: # Base case: string found
            return True
    return False


def datetime_converter(iso_string_with_z: str) -> datetime:
    """Converts an ISO 8601 string (ending with 'Z') to a timezone-aware datetime object.

    Snyk API datetime strings may include fractional seconds and a 'Z' suffix,
    which this function handles.

    Args:
        iso_string_with_z: The ISO 8601 datetime string, e.g.,
            '2025-03-01T07:10:35.20124Z'.

    Returns:
        A timezone-aware datetime object (UTC).
    """
    datetime_str_part = iso_string_with_z[:-1] # Remove the 'Z' suffix

    # Determine the correct format string based on presence of fractional seconds
    if '.' in datetime_str_part:
        format_string = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        format_string = "%Y-%m-%dT%H:%M:%S"

    dt_naive = datetime.strptime(datetime_str_part, format_string)
    dt_aware = dt_naive.replace(tzinfo=timezone.utc) # Make timezone-aware (UTC)

    return dt_aware
