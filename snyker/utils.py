def get_nested_value(data, keys, default=None):
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