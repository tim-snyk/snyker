# Project Brief: snyker

## Core Requirements and Goals

The `snyker` project is a Python-based SDK and command-line wrapper for the Snyk API. Its primary goal is to provide a convenient and powerful way to automate Snyk's security scanning and vulnerability management capabilities.

The key requirements of the project are:
- To provide a set of Pydantic models that accurately represent the core entities of the Snyk API (e.g., Groups, Organizations, Projects, Issues).
- To offer a robust `APIClient` that handles authentication, rate limiting, and retries.
- To include a `CLIWrapper` that simplifies the process of running Snyk CLI commands from within a Python script.
- To provide a set of example scripts that demonstrate how to use the SDK to perform common tasks.

## Source of Truth

The Snyk API documentation is the ultimate source of truth for the data models and API endpoints used in this project. The goal of the `snyker` library is to provide a Pythonic interface to this API.
