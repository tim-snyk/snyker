from datetime import datetime, timezone


def get_nested(data, keys, default=None):
    """Safely retrieves a nested value from a dictionary using a list of keys."""
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                index = int(key)  # Try to convert the key to an integer index
                if 0 <= index < len(current):
                    current = current[index]
                else:
                    return default  # Index out of bounds
            except ValueError:
                return default  # Key is not a valid integer index
        else:
            return default  # Current level is not a dict or list, or key not found
    return current


def search_json(json_obj, search_string):
    """
    Searches for a string in a JSON object (dict or list) across all levels against the key names and values.
    :param json_obj:
    :param search_string:
    :return:
    """
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            if search_json(value, search_string):
                return True
    elif isinstance(json_obj, list):
        for item in json_obj:
            if search_json(item, search_string):
                return True
    elif isinstance(json_obj, str):
        if search_string in json_obj:
            return True
    return False


def datetime_converter(iso_string_with_z) -> datetime:
    """
    Snyk API returns datetime strings that may not play nicely with
    Python's datetime library, especially when they include fractional seconds.
    Parses an ISO 8601 string ending with 'Z' (and potentially fractional seconds)
    into a timezone-aware datetime object (UTC).
    Example input: '2025-03-01T07:10:35.20124Z'
    """

    # Remove the 'Z' suffix
    datetime_str_part = iso_string_with_z[:-1]

    # Determine the correct format string based on presence of fractional seconds
    if '.' in datetime_str_part:
        format_string = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        format_string = "%Y-%m-%dT%H:%M:%S"

    # Parse the string to a naive datetime object
    dt_naive = datetime.strptime(datetime_str_part, format_string)

    # Make the datetime object timezone-aware by setting its timezone to UTC
    dt_aware = dt_naive.replace(tzinfo=timezone.utc)

    return dt_aware
