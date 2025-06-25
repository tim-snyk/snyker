# Contributing to Snyker SDK

First off, thank you for considering contributing to the Snyker SDK! Your help is appreciated.

## How to Contribute

We welcome contributions in various forms, including bug reports, feature requests, documentation improvements, and code contributions.

### Reporting Bugs

If you encounter a bug, please open an issue on GitHub. Include as much detail as possible:
- A clear and descriptive title.
- Steps to reproduce the bug.
- Expected behavior.
- Actual behavior.
- Snyker SDK version, Python version, and Snyk CLI version (if applicable).
- Any relevant error messages or stack traces.

### Suggesting Enhancements

If you have an idea for a new feature or an improvement to an existing one, please open an issue to discuss it. This allows us to coordinate efforts and ensure the enhancement aligns with the project's goals.

### Code Contributions

1.  **Fork the repository** and create your branch from `main`.
2.  **Set up your development environment**:
    *   We recommend using a virtual environment.
    *   Install dependencies using Poetry: `poetry install`
3.  **Make your changes**:
    *   Ensure your code adheres to the existing coding style (e.g., PEP 8).
    *   Write clear and concise commit messages.
4.  **Guidelines for AI-Assisted Development**:
    *   AI contributions are encouraged. To ensure consistency and alignment with the project's goals, all contributors (human and AI) should familiarize themselves with the project's memory bank, located in the `/memory-bank` directory.
    *   The memory bank contains key information about the project's architecture, technical decisions, and development patterns. It is designed to be cross-compatible with various AI-assisted development tools.
    *   **AI Agent Instructions - Adhere to these best practices:**
        *   **Consult the Memory Bank**: Before making any changes, review the contents of the `/memory-bank` directory to understand the project's context.
        *   **Unit Tests**: Generate unit tests for all new features and bug fixes.
        *   **Docstrings**: Add Google Python Style docstrings for all new public modules, classes, functions, and methods.
        *   **Pattern Consistency**: Maintain existing design patterns, Pydantic model usage, and SDK architecture as outlined in the memory bank.
        *   **Logging**: Implement appropriate logging (DEBUG, INFO, WARNING, ERROR).
        *   **API Compliance**: For Snyk API changes, consult the OpenAPI specification as described in the memory bank.
        *   **Avoid Cloud Features**: Do not implement or extend features related to Snyk's Cloud products (e.g., Snyk IaC interactions beyond basic project listing, specific cloud posture management API calls) as these areas may have deprecated or unstable API surfaces. Focus on core SCA, SAST, and Container features unless explicitly directed otherwise for Cloud.
5.  **Testing**:
    *   Run existing tests to ensure no regressions: `poetry run python -m unittest discover tests -v`
    *   Add new unit tests for your changes. These tests will be included in our GitHub Actions workflow to catch future regressions.
6.  **Documentation**:
    *   Update any relevant documentation (README, docstrings) to reflect your changes.
7.  **Submit a Pull Request (PR)**:
    *   Push your changes to your fork and submit a PR to the `main` branch of the Snyker repository.
    *   Provide a clear description of your changes in the PR.
    *   Link any relevant issues.

## Code Style

Please follow PEP 8 guidelines for Python code. We use Pydantic for data modeling and validation where appropriate.

## Questions?

Feel free to open an issue if you have any questions about contributing.

Thank you for your contribution!
