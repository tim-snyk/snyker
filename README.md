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

## Roadmap / Todolist

This section outlines planned features and areas for future development. Contributions are welcome! Please see `CONTRIBUTING.md`.

### Core SDK Enhancements
-   **Expand Snyk API Coverage**:
    -   **Currently Implemented Entities/Concepts**:
        -   API Client (`APIClient`)
        -   Groups (`GroupPydanticModel`)
        -   Organizations (`OrganizationPydanticModel`)
        -   Projects (`ProjectPydanticModel`)
        -   Assets (`Asset` - primarily repository type)
        -   Issues (`IssuePydanticModel`)
        -   Policies (`PolicyPydanticModel`)
        -   CLI Wrapper (`CLIWrapper`) for Snyk CLI interactions.
        -   Configuration management (from `pyproject.toml` and environment variables).
    -   **Areas for Expansion (Unimplemented Snyk API Functions)**:
        -   **User Management**: Listing users, inviting users, managing service accounts.
        -   **Reporting**: Generating and fetching various Snyk reports.
        -   **Audit Logs**: Accessing audit trails for Snyk activities.
        -   **License Compliance**: Deeper integration with Snyk's license management features.
        -   **Cloud Security**:
            -   Snyk IaC: More detailed interaction with IaC settings, test results.
            -   Snyk Cloud: Managing cloud environments, posture checks.
        -   **Container Security**: Detailed management of container image scanning results and settings.
        -   **Targets/Integrations**: More granular control over Snyk Targets and integration settings beyond basic project linking.
        -   **Project Settings**: Programmatic modification of project settings (e.g., test frequency, notifications).
        -   **Issue Management**: Actions like ignoring issues, assigning issues via API.
        -   **Collections**: Working with Snyk Collections.
        -   **More Asset Types**: Support for other asset types beyond repositories.
-   **Refine Error Handling**: More specific custom exceptions.
-   **Async Support**: Introduce an asynchronous version of the `APIClient` and SDK methods.
-   **Enhanced CLI Wrapper**: Add more Snyk CLI commands and parsing capabilities to `CLIWrapper`.

### MCP (Model Context Protocol) Server
-   **Develop an MCP Server**:
    -   **Purpose**: To provide an external, stateful service that can enhance the capabilities of AI agents using the Snyker SDK.
    -   **Deployment**: Design to be deployed as a container (e.g., Docker).
    -   **Persistence**: Incorporate memory/data persistence (e.g., using a lightweight database like SQLite, or a more robust solution if needed) to store:
        -   Cached Snyk data to reduce API calls.
        -   User preferences or configurations for the MCP server.
        -   Stateful information related to ongoing operations or analyses.
    -   **Tools/Resources**: Expose tools and resources via MCP that leverage the Snyker SDK, for example:
        -   A tool to "get_critical_vulnerabilities_for_org" which uses the SDK to fetch projects and issues, then filters.
        -   A resource representing the "current_snyk_group_summary".
-   **Documentation**: Provide clear documentation on how to build, deploy, and use the Snyker MCP server.

### Testing and CI/CD
-   **Expand Test Coverage**: Increase unit and integration test coverage for all SDK components.
    -   Include tests for various Snyk API response scenarios (e.g., empty results, errors, different data structures).
-   **Mocking**: Improve mocking for Snyk API calls in tests to make them faster and more reliable.
-   **GitHub Actions**:
    -   Enhance the existing workflow (`python-tests.yml`) to include:
        -   Linting (e.g., with Flake8 or Ruff).
        -   Code formatting checks (e.g., with Black).
        -   Building and publishing the package on new releases (e.g., to PyPI).

### Documentation
-   **API Reference**: Generate a comprehensive API reference documentation (e.g., using Sphinx).
-   **Usage Examples**: Add more diverse and advanced usage examples in the `examples/` directory.
-   **Tutorials**: Create step-by-step tutorials for common use cases.

We aim to make Snyker a powerful and easy-to-use SDK for interacting with the Snyk platform. Your contributions can help make that a reality!
