# System Patterns: snyker

## System Architecture

The `snyker` library is designed with a layered architecture:

1.  **APIClient:** This is the lowest layer, responsible for all HTTP communication with the Snyk API. It handles authentication, retries, rate limiting, and provides a thread pool for concurrent requests.

2.  **Pydantic Models:** This layer sits on top of the `APIClient`. It provides a set of Pydantic models that represent the core entities of the Snyk API (e.g., `Group`, `Organization`, `Project`, `Issue`). These models are responsible for parsing the JSON responses from the API and providing a clean, type-hinted interface to the data.

3.  **CLIWrapper:** This is a convenience layer that wraps the Snyk CLI. It uses the `APIClient` and the Pydantic models to provide a higher-level interface for automating common Snyk workflows.

## Key Technical Decisions

-   **Pydantic for Data Modeling:** Pydantic was chosen for its excellent data validation and serialization capabilities. It allows for the creation of clear, self-documenting data models that can be easily converted to and from JSON.
-   **Poetry for Dependency Management:** Poetry is used for dependency management and packaging. It provides a deterministic build process and makes it easy to manage the project's dependencies.
-   **GitHub Actions for CI/CD:** GitHub Actions is used for continuous integration and testing. The workflow is configured to run the tests and linters on every push and pull request.

## Design Patterns

-   **Lazy Loading:** The Pydantic models use a lazy loading pattern to fetch related objects from the API. For example, the `organizations` property of a `Group` object is not fetched until it is accessed for the first time. This improves performance by only fetching the data that is actually needed.
-   **Factory Method:** The `GroupPydanticModel.get_instance()` method is a factory method that provides a convenient way to create a `Group` object. It can either fetch a specific group by ID or auto-discover a single group if the API token is scoped to one.

## Component Relationships

-   A `Group` can have multiple `Organizations`.
-   An `Organization` can have multiple `Projects`.
-   A `Project` can have multiple `Issues`.
-   An `Asset` can be associated with multiple `Organizations` and `Projects`.
