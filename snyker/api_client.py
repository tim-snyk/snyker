import json
import logging
import os
import random
import time
from typing import Any, Callable, Dict, Iterator, Optional, Tuple, Union
import concurrent.futures
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from snyker.config import API_CONFIG


class APIClient:
    """
    Handles HTTP communication with the Snyk API.

    This client manages API token authentication, automatic retries for transient
    errors, rate limiting, and provides a thread pool for concurrent API calls.
    It forms the foundation for interacting with Snyk API endpoints.

    Attributes:
        base_url (str): The base URL for the Snyk API. Defaults to 'https://api.snyk.io'
                        or the value of the SNYK_API environment variable.
        token (Optional[str]): The Snyk API token. Read from the SNYK_TOKEN environment variable.
        session (requests.Session): The session object used for making HTTP requests.
        logger (logging.Logger): Logger instance for this client.
        executor (concurrent.futures.ThreadPoolExecutor): Thread pool for async tasks.
        rate_limit_delay (float): Current delay in seconds due to rate limiting.
        last_request_time (float): Timestamp of the last request made.
    """

    def __init__(
        self,
        max_retries: Optional[int] = None,
        backoff_factor: Optional[float] = None,
        status_forcelist: Optional[Tuple[int, ...]] = None,
        logging_level: Optional[int] = None,
        max_workers: Optional[int] = None,
    ):
        """Initializes the APIClient.

        Args:
            max_retries: Maximum number of retries for failed requests.
                Overrides config if provided.
            backoff_factor: Factor by which to increase delay between retries.
                Overrides config if provided.
            status_forcelist: HTTP status codes that trigger a retry.
                Overrides config if provided.
            logging_level: The logging level for the client's logger
                (e.g., `logging.DEBUG`). Overrides config if provided.
            max_workers: Max worker threads for concurrent API calls.
                Overrides config if provided. If None here and in config,
                it defaults to `min(32, os.cpu_count() + 4)`.
        """
        _max_retries = (
            max_retries if max_retries is not None else API_CONFIG["max_retries"]
        )
        _backoff_factor = (
            backoff_factor
            if backoff_factor is not None
            else API_CONFIG["backoff_factor"]
        )
        _status_forcelist = (
            status_forcelist
            if status_forcelist is not None
            else tuple(API_CONFIG["status_forcelist"])
        )
        _logging_level = (
            logging_level
            if logging_level is not None
            else API_CONFIG["logging_level_int"]
        )
        _max_workers_config = API_CONFIG.get(
            "max_workers"
        )  # Value from config can be None
        _max_workers = max_workers if max_workers is not None else _max_workers_config

        logging.basicConfig(
            level=_logging_level, format="%(asctime)s-%(levelname)s-%(message)s"
        )
        self.base_url = API_CONFIG[
            "base_url"
        ]  # SNYK_API env var is handled by config loader
        self.token = os.getenv("SNYK_TOKEN")
        if not self.token:
            logging.warning(
                "SNYK_TOKEN environment variable not set. API calls will likely fail."
            )

        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(_logging_level)

        retry_strategy = Retry(
            total=_max_retries,
            read=_max_retries,
            connect=_max_retries,
            backoff_factor=_backoff_factor,
            status_forcelist=_status_forcelist,
            allowed_methods=None,  # Retry for all HTTP methods by default
        )

        # If max_workers is still None after checking argument and config, calculate default.
        if _max_workers is None:
            _max_workers = min(32, (os.cpu_count() or 1) + 4)

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=_max_workers)
        self.logger.info(f"[APIClient] initialized with ThreadPoolExecutor (max_workers={_max_workers})")

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=_max_workers,
            pool_maxsize=_max_workers,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.rate_limit_delay = 0.0
        self.last_request_time = 0.0
        self._rate_limit_lock = threading.Lock()

    def _rate_limit(self):
        """
        Applies a delay if a rate limit was previously encountered. Thread-safe.

        This method checks if a `rate_limit_delay` is active. If so, it calculates
        the necessary wait time based on `last_request_time` and sleeps for that
        duration. This mechanism helps in respecting API rate limits across
        concurrent calls by serializing them when a limit is hit.
        """
        if self.rate_limit_delay <= 0:
            return

        with self._rate_limit_lock:
            if self.rate_limit_delay > 0:
                wait_time = self.rate_limit_delay - (
                    time.time() - self.last_request_time
                )
                if wait_time > 0:
                    self.logger.warning(
                        f"Thread {threading.get_ident()}: Rate limit active. Global wait for {wait_time:.2f} seconds."
                    )
                    time.sleep(wait_time)
                self.rate_limit_delay = 0.0  # Reset delay
                # Add a small random delay to stagger requests
                time.sleep(random.uniform(0.1, 0.5))

    def _handle_response(self, response: requests.Response) -> requests.Response:
        """
        Processes an HTTP response, handling errors and rate limit headers.

        Checks for HTTP errors and raises `requests.exceptions.HTTPError` if any.
        If a 429 (rate limit) error occurs, it updates `self.rate_limit_delay`
        based on the 'Retry-After' header.

        Args:
            response (requests.Response): The HTTP response object to process.

        Returns:
            requests.Response: The same response object if no errors occurred.

        Raises:
            requests.exceptions.HTTPError: If the response status code indicates an error.
            requests.exceptions.RequestException: For other request-related issues.
        """
        current_time = time.time()
        try:
            response.raise_for_status()
            with self._rate_limit_lock:
                self.last_request_time = current_time
            return response
        except requests.exceptions.HTTPError as e:
            with self._rate_limit_lock:
                self.last_request_time = current_time
                if response.status_code == 429:
                    self.logger.warning(
                        f"Thread {threading.get_ident()}: Rate limit error 429. Headers: {response.headers}"
                    )
                    retry_after_header = response.headers.get("Retry-After")
                    if retry_after_header and retry_after_header.isdigit():
                        self.rate_limit_delay = float(int(retry_after_header) + 1)
                    else:
                        # Fallback to configured default if header is missing or invalid
                        self.rate_limit_delay = max(
                            self.rate_limit_delay,
                            API_CONFIG["default_rate_limit_retry_after"],
                        )
                    self.logger.warning(
                        f"Thread {threading.get_ident()}: Updated rate_limit_delay to {self.rate_limit_delay}s"
                    )
                else:
                    self.logger.error(
                        f"Thread {threading.get_ident()}: API error: {response.status_code} - {e}"
                    )
                    self.logger.error(
                        f"Thread {threading.get_ident()}: Response content: {response.text}"
                    )
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Thread {threading.get_ident()}: Request exception: {e}")
            raise

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """
        Sends a GET request to the specified API endpoint.

        Args:
            endpoint (str): The API endpoint path (e.g., '/rest/users/me').
            params (Optional[Dict[str, Any]]): A dictionary of query parameters.
            headers (Optional[Dict[str, str]]): A dictionary of request headers.

        Returns:
            requests.Response: The response object from the API.
        """
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: GET request to: {url} with params: {params}, headers: {headers}")
        effective_headers = dict(self.session.headers)
        if headers:
            effective_headers.update(headers)
        if self.token and "Authorization" not in effective_headers:
            effective_headers["Authorization"] = f"token {self.token}"

        response = self.session.get(url, params=params, headers=effective_headers)
        self.logger.debug(
            f"Thread {threading.get_ident()}: GET response: {response.status_code} - {response.text[:100]}..."
        )
        return self._handle_response(response)

    def post(
        self,
        endpoint: str,
        data: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """
        Sends a POST request to the specified API endpoint.

        Args:
            endpoint (str): The API endpoint path.
            data (Optional[Any]): The JSON serializable payload for the request body.
            params (Optional[Dict[str, Any]]): A dictionary of query parameters.
            headers (Optional[Dict[str, str]]): A dictionary of request headers.

        Returns:
            requests.Response: The response object from the API.
        """
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: POST request to: {url} with params: {params}, data: {data}, headers: {headers}")
        effective_headers = dict(self.session.headers)
        if headers:
            effective_headers.update(headers)
        if self.token and "Authorization" not in effective_headers:
            effective_headers["Authorization"] = f"token {self.token}"

        response = self.session.post(
            url, params=params, json=data, headers=effective_headers
        )
        self.logger.debug(
            f"Thread {threading.get_ident()}: POST response: {response.status_code} - {response.text[:100]}..."
        )
        return self._handle_response(response)

    def put(
        self,
        endpoint: str,
        data: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """
        Sends a PUT request to the specified API endpoint.

        Args:
            endpoint (str): The API endpoint path.
            data (Optional[Any]): The JSON serializable payload for the request body.
            params (Optional[Dict[str, Any]]): A dictionary of query parameters.
            headers (Optional[Dict[str, str]]): A dictionary of request headers.

        Returns:
            requests.Response: The response object from the API.
        """
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: PUT request to: {url} with data: {data}, headers: {headers}")
        effective_headers = dict(self.session.headers)
        if headers:
            effective_headers.update(headers)
        if self.token and "Authorization" not in effective_headers:
            effective_headers["Authorization"] = f"token {self.token}"

        response = self.session.put(
            url, json=data, params=params, headers=effective_headers
        )
        self.logger.debug(
            f"Thread {threading.get_ident()}: PUT response: {response.status_code} - {response.text[:100]}..."
        )
        return self._handle_response(response)

    def delete(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """
        Sends a DELETE request to the specified API endpoint.

        Args:
            endpoint (str): The API endpoint path.
            params (Optional[Dict[str, Any]]): A dictionary of query parameters.
            headers (Optional[Dict[str, str]]): A dictionary of request headers.

        Returns:
            requests.Response: The response object from the API.
        """
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: DELETE request to: {url} with headers: {headers}")
        effective_headers = dict(self.session.headers)
        if headers:
            effective_headers.update(headers)
        if self.token and "Authorization" not in effective_headers:
            effective_headers["Authorization"] = f"token {self.token}"

        response = self.session.delete(url, params=params, headers=effective_headers)
        self.logger.debug(
            f"Thread {threading.get_ident()}: DELETE response: {response.status_code} - {response.text[:100]}..."
        )
        return self._handle_response(response)

    def submit_task(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> concurrent.futures.Future:
        """
        Submits a callable to the internal thread pool executor.

        This allows for running functions (e.g., API calls or object instantiations)
        concurrently.

        Args:
            func (Callable[..., Any]): The function or method to execute.
            *args (Any): Positional arguments to pass to the function.
            **kwargs (Any): Keyword arguments to pass to the function.

        Returns:
            concurrent.futures.Future: A Future object representing the execution
                                       of the callable.
        """
        self.logger.debug(f"Thread {threading.get_ident()}: Submitting task {getattr(func, '__name__', repr(func))} to executor.")
        return self.executor.submit(func, *args, **kwargs)

    def close(self):
        """
        Shuts down the thread pool executor.

        This method should be called when the APIClient is no longer needed to
        ensure graceful termination of worker threads. It waits for all
        submitted tasks to complete before returning.
        """
        self.logger.info(
            f"Thread {threading.get_ident()}: Shutting down ThreadPoolExecutor."
        )
        self.executor.shutdown(wait=True)

    def _get_next_page(
        self,
        response_json: Dict[str, Any],
        pagination_key: str,
    ) -> Optional[str]:
        links = response_json.get("links", {})
        if isinstance(links, dict):
            return links.get(pagination_key)
        return None

    def paginate(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        pagination_key: str = "next",
        data_key: Optional[str] = None,
        max_pages: Optional[int] = None,
        **kwargs: Any,
    ) -> Iterator[Union[Dict[str, Any], Any]]:
        """Handles pagination for GET requests, yielding items or pages."""
        current_params = params.copy() if params else {}
        page_count = 0

        if "limit" not in current_params:
            current_params["limit"] = API_CONFIG.get("default_page_limit", 100)

        next_page_url: Optional[str] = endpoint

        while next_page_url and (max_pages is None or page_count < max_pages):
            response_obj = self.get(endpoint=next_page_url, params=current_params, **kwargs)
            page_count += 1

            try:
                response_json = response_obj.json()
            except json.JSONDecodeError as e_json:
                self.logger.error(f"JSONDecodeError on page {page_count}: {e_json}")
                break

            if data_key:
                items = response_json.get(data_key)
                if items is not None and isinstance(items, list):
                    yield from items
                elif items is not None:
                    self.logger.warning(f"Data key '{data_key}' is not a list.")
                    yield items
                else:
                    self.logger.warning(f"Data key '{data_key}' not found in response.")
                    break
            else:
                yield response_json

            next_page_url = self._get_next_page(response_json, pagination_key)
            current_params = {}
