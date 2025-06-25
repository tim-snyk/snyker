# Technical Context: snyker

## Technologies Used

-   **Python:** The core language of the project. The code is written to be compatible with Python 3.11 and later.
-   **Pydantic:** Used for data validation and serialization. All of the Snyk API data models are built with Pydantic.
-   **Poetry:** Used for dependency management and packaging.
-   **Requests:** Used for making HTTP requests to the Snyk API.
-   **Pytest:** Used for running the unit and integration tests.
-   **Flake8:** Used for linting the code.
-   **GitHub Actions:** Used for CI/CD.

## Development Setup

To set up the development environment, you will need:
-   Python 3.11 or later.
-   Poetry.

Once you have these installed, you can set up the project with the following commands:
```bash
poetry install
```

## Technical Constraints

-   The project must be compatible with Python 3.11 and later.
-   The project must be able to handle the rate limiting and pagination of the Snyk API.
-   The project must be well-tested to ensure its reliability.

## Dependencies

The project's dependencies are managed by Poetry and are listed in the `pyproject.toml` file. The main dependencies are:
-   `requests`
-   `urllib3`
-   `pydantic`

The development dependencies are:
-   `flake8`
-   `black`
-   `pytest`

## Tool Usage Patterns

-   **Poetry:** Used for all dependency management, packaging, and running scripts and tests.
-   **Pytest:** Used for running the unit and integration tests. The tests are located in the `tests` directory.
-   **Flake8:** Used for linting the code. The configuration is in the `pyproject.toml` file.
-   **GitHub Actions:** Used to automate the testing and linting process. The workflow is defined in `.github/workflows/python-tests.yml`.

## Coding Standards

-   **Google Python Style Guide:** The project should adhere to the Google Python Style Guide.
-   **PEP 8:** The code should be compliant with the PEP 8 style guide.
-   **Docstrings:** All modules, classes, and functions should have comprehensive docstrings that follow the Google Python Style Guide.
-   **AI-Friendly Code:** The code should be written in a way that is easy for AI models to understand and reason about. This includes using clear and descriptive variable names, writing simple and focused functions, and providing type hints for all function signatures.
