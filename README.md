# Snyker SDK

DISCLAIMER: This is just a personal project and not officially covered by support nor directly endorsed by Snyk.

**Required Environment Variables:**

`SNYK_TOKEN`: Snyk API token - recommended as Group Admin Service Account token to access all tools while avoiding ambiguities due to access to multiple Snyk Groups

`API_URL`: Snyk API URL (default: https://api.snyk.io) read more about regional API endpoints at the following
[link](https://docs.snyk.io/working-with-snyk/regional-hosting-and-data-residency#available-snyk-regions)

## Quickstart: Running the Basic SDK Usage Example

This guide will walk you through setting up and running the `examples/basic_sdk_usage.py` script, which demonstrates core functionalities of the `snyker` SDK.

### Prerequisites

1.  **Python**: Ensure you have Python 3.11 or newer installed (as specified in `pyproject.toml`). You can check your Python version by running:
    ```bash
    python --version 
    python3 --version
    ```
2.  **Poetry**: This project uses Poetry for dependency management and packaging. If you don't have Poetry installed, follow the instructions on the [official Poetry website](https://python-poetry.org/docs/#installation).

### Setup Instructions

1.  **Clone the Repository**:
    If you haven't already, clone the `snyker` repository to your local machine:
    ```bash
    git clone <repository_url> 
    # Replace <repository_url> with the actual URL of the snyker repository
    cd snyker
    ```

2.  **Install Dependencies**:
    Navigate to the root directory of the cloned project (the one containing `pyproject.toml`) and install the dependencies using Poetry:
    ```bash
    poetry install
    ```
    This command will create a virtual environment if one doesn't exist and install all necessary packages defined in `pyproject.toml`.

3.  **Set Environment Variables**:
    The SDK requires a Snyk API token to authenticate with the Snyk API.
    *   **`SNYK_TOKEN`**: Set this environment variable to your Snyk API token. It's recommended to use a Group-scoped Service Account token for full access and to avoid ambiguity if your user account has access to multiple Snyk Groups.
        ```bash
        export SNYK_TOKEN="your_snyk_api_token_here"
        ```
        (On Windows, use `set SNYK_TOKEN=your_snyk_api_token_here` in Command Prompt or `$env:SNYK_TOKEN="your_snyk_api_token_here"` in PowerShell).
    *   **`SNYK_API` (Optional)**: If you need to use a Snyk API endpoint other than the default (`https://api.snyk.io`), set the `SNYK_API` environment variable. For example, for the AU region:
        ```bash
        export SNYK_API="https://api.au.snyk.io"
        ```
        Refer to the [Snyk regional hosting documentation](https://docs.snyk.io/working-with-snyk/regional-hosting-and-data-residency#available-snyk-regions) for other available endpoints. If not set, the SDK defaults to `https://api.snyk.io`.

### Running the Example Script

Once the setup is complete, you can run the `basic_sdk_usage.py` script from the root directory of the project using Poetry:

```bash
poetry run python examples/basic_sdk_usage.py
```

**Note on Python command**:
*   The command `python` is used above. If your system's default `python` command points to Python 2, or if `python` is not aliased to your Python 3 installation, you might need to use `python3` instead:
    ```bash
    poetry run python3 examples/basic_sdk_usage.py
    ```

The script will initialize the `APIClient`, connect to your Snyk Group (it's currently hardcoded in the example to use a specific test Group ID; you might need to adjust this if that ID isn't relevant for your token), and demonstrate fetching various Snyk entities like organizations, projects, and issues. The output will be logged to your console, showing INFO level messages by default.

This should provide a good starting point for understanding how to use the `snyker` SDK.
