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
4.  **AI-Assisted Changes**:
    *   AI-assisted changes are welcome! We encourage leveraging AI tools to help with development.
    *   **Crucially, when using AI assistance for code generation or modification, please prompt the AI to incorporate best practices, including:**
        *   **Unit Tests**: All new features or bug fixes should be accompanied by corresponding unit tests. These tests are vital for ensuring code quality and preventing regressions. AI should be prompted to help generate these tests.
        *   **Docstrings**: All new public modules, classes, functions, and methods should have clear and comprehensive docstrings (Google Python Style). AI can assist in generating initial docstrings.
        *   **Pattern Consistency**: Ensure that AI-generated code aligns with the existing design patterns, Pydantic model usage, and overall architecture of the Snyker SDK.
        *   **Logging**: Incorporate appropriate logging (DEBUG, INFO, WARNING, ERROR) for new functionality.
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
