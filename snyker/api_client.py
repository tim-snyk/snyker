import json
import logging
import os
import time
from typing import Dict, Any, Optional
import concurrent.futures
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class APIClient:
    def __init__(self,
                 max_retries=15,
                 backoff_factor=0.5,
                 status_forcelist=(429, 500, 502, 503, 504),
                 logging_level=10,  # 10 = DEBUG, 20 = INFO, 30 = WARNING, 40 = ERROR, 50 = CRITICAL
                 max_workers: Optional[int] = None
                 ):

        logging.basicConfig(level=logging_level, format='%(asctime)s-%(levelname)s-%(message)s')
        self.base_url = os.getenv('SNYK_API',               # Get region url from SNYK_API environment variable
                                  "https://api.snyk.io")    # Default to US_MT_GCP
        self.token = os.getenv('SNYK_TOKEN')  # Get your API token from SNYK_TOKEN environment variable
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        retry_strategy = Retry(  # Renamed from retry to avoid conflict
            total=max_retries,
            read=max_retries,
            connect=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            allowed_methods=None  # Retry on any 'requests' method
        )
        if max_workers is None:
            max_workers = min(32, (os.cpu_count() or 1) + 4)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.logger.info(f"[APIClient] initialized with ThreadPoolExecutor (max_workers={max_workers})")

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=max_workers,
            pool_maxsize=max_workers
            )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.rate_limit_delay = 0
        self.last_request_time = 0
        self._rate_limit_lock = threading.Lock()  # Thread safety first!




    def _rate_limit(self):
        """Applies a delay if a rate limit was previously encountered. Thread-safe."""
        # Quick check without lock first for performance
        if self.rate_limit_delay <= 0:
            return

        with self._rate_limit_lock:
            if self.rate_limit_delay > 0:
                wait_time = self.rate_limit_delay - (time.time() - self.last_request_time)
                if wait_time > 0:
                    self.logger.warning(f"Thread {threading.get_ident()}: Rate limit active. Global wait for {wait_time:.2f} seconds.")
                    # This sleep will pause the current thread holding the lock, effectively serializing
                    # API-calling operations across threads when a rate limit is hit.
                    time.sleep(wait_time)
                self.rate_limit_delay = 0 # Reset delay after waiting or if wait_time was not positive

    def _handle_response(self, response: requests.Response) -> Any:
        current_time = time.time()
        try:
            response.raise_for_status()
            # Successfully handled, update last_request_time if needed for future rate limit logic
            with self._rate_limit_lock:
                self.last_request_time = current_time
            return response
        except requests.exceptions.HTTPError as e:
            with self._rate_limit_lock:
                self.last_request_time = current_time # Update time even on error
                if response.status_code == 429:
                    self.logger.warning(f"Thread {threading.get_ident()}: Rate limit error 429. Headers: {response.headers}")
                    retry_after = response.headers.get('Retry-After')
                    if retry_after and retry_after.isdigit():
                        self.rate_limit_delay = int(retry_after) + 1 # Add a small buffer
                    else:
                        # Default delay if Retry-After is not present or not a digit
                        self.rate_limit_delay = max(self.rate_limit_delay, 5) # Use existing if larger, or default
                    self.logger.warning(f"Thread {threading.get_ident()}: Updated rate_limit_delay to {self.rate_limit_delay}s")
                else:
                    self.logger.error(f"Thread {threading.get_ident()}: API error: {response.status_code} - {e}")
                    self.logger.error(f"Thread {threading.get_ident()}: Response content: {response.text}")
            raise # Re-raise the original exception
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Thread {threading.get_ident()}: Request exception: {e}")
            raise

    def get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> Any:
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: GET request to: {url} with params: {params}, headers: {headers}")
        response = self.session.get(url, params=params, headers=headers)
        self.logger.debug(
            f"Thread {threading.get_ident()}: GET response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def post(self, endpoint, data=None, params=None, headers=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: POST request to: {url} with params: {params}, data: {data}, headers: {headers}")
        response = self.session.post(url, params=params, json=data, headers=headers)
        self.logger.debug(f"Thread {threading.get_ident()}: POST response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def put(self, endpoint, data=None, params=None, headers=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: PUT request to: {url} with data: {data}, headers: {headers}")
        response = self.session.put(url, json=data, params=params, headers=headers)
        self.logger.debug(f"Thread {threading.get_ident()}: PUT response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def delete(self, endpoint, params=None, headers=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"Thread {threading.get_ident()}: DELETE request to: {url} with headers: {headers}")
        response = self.session.delete(url, params=params, headers=headers)
        self.logger.debug(f"Thread {threading.get_ident()}: DELETE response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def submit_task(self, func, *args, **kwargs) -> concurrent.futures.Future:
        """Submits a callable to the internal thread pool executor."""
        self.logger.debug(f"Thread {threading.get_ident()}: Submitting task {getattr(func, '__name__', repr(func))} to executor.")
        return self.executor.submit(func, *args, **kwargs)

    def close(self):
        """Shuts down the thread pool executor. Call this when APIClient is no longer needed."""
        self.logger.info(f"Thread {threading.get_ident()}: Shutting down ThreadPoolExecutor.")
        self.executor.shutdown(wait=True)

    def paginate(self, endpoint: str, params: Optional[Dict] = None,
                 pagination_key: str = 'next', data_key: Optional[str] = None,
                 max_pages: Optional[int] = None, **kwargs) -> Any:
        """
        Handles pagination for GET requests.
        Yields individual items if data_key is provided, otherwise the entire JSON response for each page.
        """
        current_params = params.copy() if params else {}
        page_count = 0
        if endpoint.startswith(self.base_url):
            next_page_url_or_relative_path = endpoint  # It's a full URL
        else:
            next_page_url_or_relative_path = endpoint  # It's a relative path
        while next_page_url_or_relative_path and (max_pages is None or page_count < max_pages):
            # Determine if we have a full URL or a relative path for self.get
            if next_page_url_or_relative_path.startswith(self.base_url):
                api_endpoint_path = next_page_url_or_relative_path.replace(f"{self.base_url}/", "", 1)
                call_params = None if page_count > 0 else current_params
            else:
                api_endpoint_path = next_page_url_or_relative_path
                call_params = current_params # Use current_params for relative paths

            response_obj = self.get(endpoint=api_endpoint_path, params=call_params, **kwargs)
            page_count += 1
            response_json = response_obj.json()

            if data_key:
                items = response_json.get(data_key)
                if items is not None: # Check for None explicitly, as empty list is valid
                    yield from items
                else:
                    self.logger.warning(f"Data key '{data_key}' not found in response for {api_endpoint_path} page {page_count}")
                    break
            else:
                yield response_json

            # Handle next page link (Snyk specific: often in response_json['links']['next'])
            links = response_json.get("links", {})
            next_page_url_or_relative_path = links.get(pagination_key)

            if not next_page_url_or_relative_path:
                self.logger.debug(f"No '{pagination_key}' link found in pagination, ending pagination after {page_count} pages.")
                break
            else:
                current_params = None # Assume 'next' link is self-contained or new params will be derived
                self.logger.debug(f"Next page link for pagination: {next_page_url_or_relative_path}")


# Example Usage:
if __name__ == "__main__":
    api_client = APIClient(max_retries=15, backoff_factor=1)
    try:
        uri = f"/rest/openapi"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{api_client.token}'
        }
        data = api_client.get(uri, headers=headers)
        print("GET Response:", json.dumps(data.json(), indent=4))
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
