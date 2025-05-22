import tomllib
import os
import logging
from typing import Dict, Any, List, Tuple, Optional

CONFIG_FILE_PATH = "pyproject.toml"

DEFAULT_API_CLIENT_CONFIG = {
    "base_url": "https://api.snyk.io",
    "max_retries": 15,
    "backoff_factor": 0.5,
    "status_forcelist": [429, 500, 502, 503, 504],
    "logging_level": "INFO",
    "max_workers": None,  # If None, will be calculated as min(32, os.cpu_count() + 4)
    "default_rate_limit_retry_after": 5.0,
    "loading_strategy": "lazy" # Options: "lazy", "eager"
}

def get_logging_level_from_string(level_str: str) -> int:
    """Converts a logging level string to its integer value."""
    return getattr(logging, level_str.upper(), logging.INFO)

def load_api_client_config() -> Dict[str, Any]:
    """
    Loads API client configuration from pyproject.toml.
    Falls back to default values if the file or specific keys are not found.
    Environment variables `SNYK_API` and `SNYK_TOKEN` will override relevant settings.
    """
    config = DEFAULT_API_CLIENT_CONFIG.copy()

    try:
        with open(CONFIG_FILE_PATH, "rb") as f:
            data = tomllib.load(f)
            tool_snyker_config = data.get("tool", {}).get("snyker", {})
            
            api_client_settings = tool_snyker_config.get("api_client", {})
            if api_client_settings:
                config["base_url"] = api_client_settings.get("base_url", config["base_url"])
                config["max_retries"] = api_client_settings.get("max_retries", config["max_retries"])
                config["backoff_factor"] = api_client_settings.get("backoff_factor", config["backoff_factor"])
                
                status_forcelist_from_toml = api_client_settings.get("status_forcelist", config["status_forcelist"])
                if isinstance(status_forcelist_from_toml, list) and all(isinstance(x, int) for x in status_forcelist_from_toml):
                    config["status_forcelist"] = tuple(status_forcelist_from_toml)
                else:
                    logging.getLogger(__name__).warning(
                        f"Invalid format for 'status_forcelist' in {CONFIG_FILE_PATH}. Using default. "
                        f"Expected list of integers, got: {status_forcelist_from_toml}"
                    )
                    config["status_forcelist"] = tuple(DEFAULT_API_CLIENT_CONFIG["status_forcelist"])

                config["logging_level"] = api_client_settings.get("logging_level", config["logging_level"])
                config["max_workers"] = api_client_settings.get("max_workers", config["max_workers"])
                config["default_rate_limit_retry_after"] = api_client_settings.get("default_rate_limit_retry_after", config["default_rate_limit_retry_after"])

            sdk_settings = tool_snyker_config.get("sdk_settings", {})
            if sdk_settings:
                config["loading_strategy"] = sdk_settings.get("loading_strategy", config["loading_strategy"])
                if config["loading_strategy"] not in ["lazy", "eager"]:
                    logging.getLogger(__name__).warning(
                        f"Invalid 'loading_strategy': {config['loading_strategy']} in {CONFIG_FILE_PATH}. "
                        f"Using default '{DEFAULT_API_CLIENT_CONFIG['loading_strategy']}'. Allowed values: 'lazy', 'eager'."
                    )
                    config["loading_strategy"] = DEFAULT_API_CLIENT_CONFIG["loading_strategy"]

    except FileNotFoundError:
        logging.getLogger(__name__).info(f"{CONFIG_FILE_PATH} not found. Using default configurations.")
    except tomllib.TOMLDecodeError:
        logging.getLogger(__name__).error(f"Error decoding {CONFIG_FILE_PATH}. Using default configurations.")
    except Exception as e:
        logging.getLogger(__name__).error(f"Unexpected error loading config from {CONFIG_FILE_PATH}: {e}. Using defaults.")

    # Environment variables override pyproject.toml settings for specific items.
    config["base_url"] = os.getenv('SNYK_API', config["base_url"])
    # SNYK_TOKEN is handled directly in APIClient.

    # Convert logging_level string to its integer representation.
    config["logging_level_int"] = get_logging_level_from_string(str(config["logging_level"]))

    return config

# Load configuration once when the module is imported.
API_CONFIG = load_api_client_config()

if __name__ == '__main__':
    # This block is for testing the config loader directly.
    print("Loaded API Client Configuration:")
    for key, value in API_CONFIG.items():
        print(f"  {key}: {value}")
