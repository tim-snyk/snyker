import json
import logging
import os
import time
from typing import Dict, Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class APIClient:
    def __init__(self,
                 max_retries=15,
                 backoff_factor=0.5,
                 status_forcelist=(429, 500, 502, 503, 504),
                 logging_level=10): # 10 = DEBUG, 20 = INFO, 30 = WARNING, 40 = ERROR, 50 = CRITICAL

        logging.basicConfig(level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.base_url = os.getenv('SNYK_API',               # Get region url from SNYK_API environment variable
                                  "https://api.snyk.io")    # Default to US_MT_GCP
        self.token = os.getenv('SNYK_TOKEN')  # Get your API token from SNYK_TOKEN environment variable
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        retry = Retry(
            total=max_retries,
            read=max_retries,
            connect=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            allowed_methods=None  # Retry on any 'requests' method
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.rate_limit_delay = 0
        self.last_request_time = 0

    def _rate_limit(self):
        """Applies a delay if a rate limit was previously encountered."""
        if self.rate_limit_delay > 0:
            wait_time = self.rate_limit_delay - (time.time() - self.last_request_time)
            if wait_time > 0:
                self.logger.warning(f"Rate limit encountered. Waiting for {wait_time:.2f} seconds.")
                time.sleep(wait_time)
            self.rate_limit_delay = 0

    def _handle_response(self, response: requests.Response) -> Any:
        self.last_request_time = time.time()
        try:
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                self.logger.warning(
                    f"Rate limit encountered: {response.status_code} - {response.headers.get('Retry-After', 'no retry info')}")
                retry_after = response.headers.get('Retry-After')
                if retry_after and retry_after.isdigit():
                    self.rate_limit_delay = int(retry_after) + 1
                else:
                    self.rate_limit_delay = self.rate_limit_delay if self.rate_limit_delay > 0 else 5
                raise
            else:
                self.logger.error(f"API error: {response.status_code} - {e}")
                self.logger.error(f"Response content: {response.text}")
                raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request exception: {e}")
            raise

    def get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> Any:
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"GET request to: {url} with params: {params}, headers: {headers}")
        response = self.session.get(url, params=params, headers=headers)
        self.logger.debug(
            f"GET response: {response.status_code} - {response.text[:100]}...")  # Log first 100 chars of response
        return self._handle_response(response)

    def post(self, endpoint, data=None, params=None, headers=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"POST request to: {url} with params: {params}, data: {data}, headers: {headers}")
        response = self.session.post(url, params=params, json=data, headers=headers)
        self.logger.debug(f"POST response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def put(self, endpoint, data=None, params=None, headers=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"PUT request to: {url} with data: {data}, headers: {headers}")
        response = self.session.put(url, json=data, params=params, headers=headers)
        self.logger.debug(f"PUT response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def delete(self, endpoint, params=None, headers=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self.logger.debug(f"DELETE request to: {url} with headers: {headers}")
        response = self.session.delete(url, params=params, headers=headers)
        self.logger.debug(f"DELETE response: {response.status_code} - {response.text[:100]}...")
        return self._handle_response(response)

    def paginate(self, endpoint: str, params: Optional[Dict] = None,
                 pagination_key: str = 'next', data_key: Optional[str] = None,
                 max_pages: Optional[int] = None, **kwargs) -> Any:
        """
        Handles pagination for GET requests.

        Args:
            endpoint: The API endpoint to paginate.
            params: Initial query parameters.
            pagination_key: The key in the response that contains the URL or token for the next page.
                            Set to None if pagination is handled differently (e.g., by page number).
            data_key: An optional key to extract the list of items from each page's response.
            max_pages: The maximum number of pages to retrieve. If None, it will continue until
                       no next page is indicated.
            **kwargs: Additional keyword arguments to pass to the self.get() method.

        Yields:
            Individual items if data_key is provided, otherwise the entire response for each page.
        """
        current_params = params.copy() if params else {}
        page_count = 0
        next_page_url = f"{self.base_url}/{endpoint.lstrip('/')}"

        while next_page_url and (max_pages is None or page_count < max_pages):
            response = self.get(endpoint=next_page_url.replace(f"{self.base_url}/", ""),
                                params=current_params, **kwargs)
            page_count += 1

            if data_key:
                items = response.get(data_key)
                if items:
                    yield from items
                else:
                    self.logger.warning(f"Data key '{data_key}' not found in response for {next_page_url}")
                    break  # Or handle differently
            else:
                yield response

            if pagination_key:
                next_page_url = response.get(pagination_key)
                if next_page_url and not next_page_url.startswith('http'):
                    next_page_url = f"{self.base_url}/{next_page_url.lstrip('/')}"
                elif not next_page_url:
                    break
            else:
                # If no pagination_key, assume pagination is handled by a parameter
                # You might need to adjust the parameter name based on the API
                if 'page' in current_params:
                    current_params['page'] += 1
                else:
                    current_params['page'] = 2  # Start from page 2 if 'page' not initially present

                # You'll need a condition to determine when to stop if no 'next' link
                # This might involve checking if the current page returns an empty dataset
                if not response.get(data_key):  # Example stop condition
                    break
                next_page_url = f"{self.base_url}/{endpoint.lstrip('/')}"  # Keep the base URL


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
