"""
main.py

A simple entry point for the Snyk SDK (snyker).
This script demonstrates basic initialization and points to more comprehensive examples.

Prerequisites:
- Ensure the 'snyker' package is installed.
- Set the SNYK_TOKEN environment variable with a Snyk Group-scoped Service Account token.
"""
from snyker import Group, APIClient
import os

def main():
    """
    A minimal demonstration of the snyker SDK.
    """

    snyk_token = os.getenv("SNYK_TOKEN")
    if not snyk_token:
        print("Error: SNYK_TOKEN environment variable not set.")
        print("Please set it with your Snyk Group-scoped Service Account token.")
        return

    print("Initializing Snyk APIClient...")
    # Initialize the APIClient.
    # You can customize parameters like max_retries, backoff_factor, logging_level.
    # Logging level: 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL
    api_client = APIClient(logging_level=20) # Default is INFO

    print("Initializing Snyk Group...")
    try:
        # Initialize the Group.
        # If your token is associated with multiple Snyk Groups, you might need to
        # provide a specific 'group_id' (e.g., group = Group(group_id="your-group-id", api_client=api_client)).
        group = Group(api_client=api_client)
        print(f"Successfully connected to Snyk Group: '{group.name}' (ID: {group.id})")
        print(f"SDK Version (example, not a real SDK attribute): snyker 0.1.0") # Placeholder for SDK version if available

    except ValueError as e:
        print(f"Error initializing Snyk Group: {e}")
        print("This can happen if your SNYK_TOKEN is associated with multiple groups and a specific group_id was not provided.")
        print("Try: group = Group(group_id='your-actual-group-id', api_client=api_client)")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Important: Always close the APIClient when done to clean up resources.
        if 'api_client' in locals() and api_client:
            print("Closing API client...")
            api_client.close()

    print("\nFor more detailed examples of how to use the snyker SDK,")
    print("please see the script in the 'examples/' directory:")
    print("  python examples/basic_sdk_usage.py")
    print("\nScript finished.")

if __name__ == "__main__":
    main()
