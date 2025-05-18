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


