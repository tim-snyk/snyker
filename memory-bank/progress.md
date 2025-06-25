# Progress: snyker

## What Works

-   The core SDK models (`Group`, `Organization`, `Project`, `Issue`, `Policy`, `Asset`, `PackageURL`) are implemented and can be used to interact with the Snyk API.
-   The `APIClient` correctly handles authentication, rate limiting, and retries.
-   The `CLIWrapper` can be used to run Snyk CLI commands from within a Python script.
-   The example scripts demonstrate how to use the SDK to perform common tasks, such as:
    -   Fetching organizations, projects, and issues.
    -   Exporting policies.
    -   Finding issues by PURL.
    -   Implementing a CI/CD gating workflow.
-   The project is fully managed by Poetry.
-   The CI/CD pipeline is configured to run tests and linters on every push and pull request.
-   The test suite is reasonably fast and provides good coverage of the core SDK models.

## What's Left to Build

-   More comprehensive test coverage, especially for the `CLIWrapper` and the more complex API interactions.
-   More example scripts to demonstrate other common use cases.
-   More complete documentation, including a user guide and API reference.

## Current Status

The project is in a good state. The core functionality is implemented and well-tested. The CI/CD pipeline is set up and working correctly. The main focus now is on improving the documentation and adding more examples to make the library easier to use.

## Known Issues

-   The Snyk API has some inconsistencies in its data models, which can make it tricky to create Pydantic models that work for all cases.
-   The Snyk API has some asynchronous operations that require polling, which can make the SDK a bit more complex to use.

## Evolution of Project Decisions

-   The project was initially using a mix of `uv` and `poetry` for dependency management. It has now been unified to use Poetry for everything.
-   The tests were initially making live API calls, which made them slow and unreliable. They have now been simplified to be faster and more focused.
-   The project has evolved from a simple collection of scripts to a more structured SDK with a clear architecture and a growing set of features.
