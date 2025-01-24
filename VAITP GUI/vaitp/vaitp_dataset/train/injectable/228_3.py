import logging
import os
import re
import threading
import time
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class SnowflakeHTTPAdapter(HTTPAdapter):
    """
    Transport Adapter that retries on specific HTTP status codes.
    """

    def __init__(self, max_retries=3, *args, **kwargs):
        retry = Retry(
            total=max_retries,
            read=max_retries,
            connect=max_retries,
            backoff_factor=0.3,
            status_forcelist=(
                405,  # Method Not Allowed
                408,  # Request Timeout
                429,  # Too Many Requests
                500,  # Internal Server Error
                502,  # Bad Gateway
                503,  # Service Unavailable
                504,  # Gateway Timeout
            ),
            allowed_methods=Retry.DEFAULT_ALLOWED_METHODS.union(
                {"POST", "GET", "PUT", "DELETE"}
            ),
        )
        super(SnowflakeHTTPAdapter, self).__init__(max_retries=retry, *args, **kwargs)

    def send(self, request, **kwargs):
        try:
            return super(SnowflakeHTTPAdapter, self).send(request, **kwargs)
        except requests.exceptions.RequestException as e:
             logger.debug(f"Request failed with exception {e}, retrying.")
             return super(SnowflakeHTTPAdapter, self).send(request, **kwargs)

def _get_default_user_agent():
    """
    Construct the user agent string to be sent to Snowflake
    """
    try:
        import platform
        import sys
        import snowflake.connector

        os_name = platform.system()
        os_version = platform.release()
        python_version = sys.version.replace("\n", " ")
        connector_version = snowflake.connector.__version__
        user_agent = f"snowflake-connector-python/{connector_version} "
        user_agent += f"({os_name}; {os_version}; {python_version})"
        return user_agent
    except Exception as e:
        logger.debug(f"Failed to construct user agent string: {e}")
        return "snowflake-connector-python"

def _create_http_session(
    max_connection_pool: int = 10,
    connect_timeout: int = 60,
    request_timeout: int = 60,
    user_agent: Optional[str] = None,
    proxy_host: Optional[str] = None,
    proxy_port: Optional[int] = None,
    proxy_user: Optional[str] = None,
    proxy_password: Optional[str] = None,
    use_openssl_only: bool = False,
) -> requests.Session:
    """Creates a HTTP session.

    Args:
        max_connection_pool (int): Max number of connections in the pool
        connect_timeout (int): Connection timeout in seconds
        request_timeout (int): Request timeout in seconds
        user_agent (str): User agent
        proxy_host (str): Proxy server host name
        proxy_port (int): Proxy server port number
        proxy_user (str): Proxy server user
        proxy_password (str): Proxy server password
        use_openssl_only (bool): Use OpenSSL only if set True

    Returns:
        requests.Session: HTTP session
    """
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent or _get_default_user_agent()})
    adapter = SnowflakeHTTPAdapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.verify = True

    session.timeout = (connect_timeout, request_timeout)
    
    if proxy_host:
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        if proxy_user and proxy_password:
            proxy_url = f"http://{proxy_user}:{proxy_password}@{proxy_host}:{proxy_port}"
        session.proxies.update({"http": proxy_url, "https": proxy_url})

    return session


class RetryCounter:
    def __init__(self):
        self._count = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self._count += 1

    def value(self):
        with self._lock:
            return self._count
        
    def reset(self):
        with self._lock:
            self._count = 0
            
class SnowflakeRestAPI:
    """
    Snowflake Rest API
    """

    _URL_BASE = "/v1"
    _URL_LOGIN_REQUEST = _URL_BASE + "/login-request"
    _URL_AUTHENTICATOR_REQUEST = _URL_BASE + "/authenticator-request"
    _URL_QUERY = _URL_BASE + "/query/v1"
    _URL_QUERY_CANCEL = _URL_BASE + "/query/v1/cancel"
    _URL_UPLOAD = _URL_BASE + "/upload"
    _URL_DOWNLOAD = _URL_BASE + "/download"
    _URL_SF_STORAGE = _URL_BASE + "/sfstorage"
    _URL_SESSION = _URL_BASE + "/session"
    _URL_DATA = _URL_BASE + "/data"
    _URL_OCSP_RESPONSE = _URL_BASE + "/ocsp/response"
    _URL_GET_LATEST_TELEMETRY = _URL_BASE + "/telemetry/get_latest"
    _URL_INSERT_TELEMETRY = _URL_BASE + "/telemetry/insert"

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        connection_pool_size: int = 10,
        connect_timeout: int = 60,
        request_timeout: int = 60,
        user_agent: Optional[str] = None,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        proxy_user: Optional[str] = None,
        proxy_password: Optional[str] = None,
        use_openssl_only: bool = False,
        application: Optional[str] = None,
        application_version: Optional[str] = None,
    ):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._connection_pool_size = connection_pool_size
        self._connect_timeout = connect_timeout
        self._request_timeout = request_timeout
        self._user_agent = user_agent
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_user = proxy_user
        self._proxy_password = proxy_password
        self._use_openssl_only = use_openssl_only
        self._application = application
        self._application_version = application_version
        self._session = _create_http_session(
            max_connection_pool=self._connection_pool_size,
            connect_timeout=self._connect_timeout,
            request_timeout=self._request_timeout,
            user_agent=self._user_agent,
            proxy_host=self._proxy_host,
            proxy_port=self._proxy_port,
            proxy_user=self._proxy_user,
            proxy_password=self._proxy_password,
            use_openssl_only=self._use_openssl_only,
        )
        self._base_url = f"{self._protocol}://{self._host}:{self._port}"
        self._request_guid = None
        self._retry_counter = RetryCounter()
    
    def _request(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[Tuple[int, int]] = None,
        is_raw_text: bool = False,
        no_retry: bool = False,
        _request_id: Optional[str] = None,
        
    ) -> requests.Response:
        """Sends a request to the server.

        Args:
            url (str): URL
            method (str): HTTP method
            headers (dict): HTTP headers
            json (dict): JSON data
            data (str): Raw data
            params (dict): Query parameters
            timeout (tuple): Timeout
            is_raw_text (bool): If the response must be decoded as raw text
            no_retry (bool): If the request should not be retried
            _request_id (str): Request ID for logging

        Returns:
            requests.Response: HTTP response object
        """
        headers = headers or {}
        if self._application:
            headers["X-Snowflake-Application"] = self._application
        if self._application_version:
            headers["X-Snowflake-Application-Version"] = self._application_version

        if _request_id:
            headers["X-Snowflake-Request-ID"] = _request_id
        
        if self._request_guid:
             headers["X-Snowflake-Request-GUID"] = self._request_guid

        try:
            resp = self._session.request(
                 method=method,
                 url=url,
                 headers=headers,
                 json=json,
                 data=data,
                 params=params,
                 timeout=timeout or self._session.timeout,
             )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            if not no_retry and self._retry_counter.value() < 5:
                logger.debug(f"Request failed with exception {e}, retrying.")
                self._retry_counter.increment()
                time.sleep(0.5 * self._retry_counter.value())
                return self._request(url, method, headers, json, data, params, timeout, is_raw_text, no_retry, _request_id)
            else:
                logger.error(f"Request failed with exception {e} after {self._retry_counter.value()} retries.")
                self._retry_counter.reset()
                raise e

        self._retry_counter.reset()
        return resp
    
    def post_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[Tuple[int, int]] = None,
        is_raw_text: bool = False,
        no_retry: bool = False,
        _request_id: Optional[str] = None
    ) -> requests.Response:
            """Sends a POST request to the server.

            Args:
                url (str): URL
                headers (dict): HTTP headers
                json (dict): JSON data
                data (str): Raw data
                params (dict): Query parameters
                timeout (tuple): Timeout
                is_raw_text (bool): If the response must be decoded as raw text
                no_retry (bool): If the request should not be retried
                _request_id (str): Request ID for logging
            Returns:
                requests.Response: HTTP response object
            """
            return self._request(
               url=url,
                method="POST",
                headers=headers,
                json=json,
                data=data,
                params=params,
                timeout=timeout,
                is_raw_text=is_raw_text,
                no_retry=no_retry,
                _request_id=_request_id,
            )

    def get_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[Tuple[int, int]] = None,
        is_raw_text: bool = False,
        no_retry: bool = False,
        _request_id: Optional[str] = None
    ) -> requests.Response:
        """Sends a GET request to the server.

        Args:
            url (str): URL
            headers (dict): HTTP headers
            params (dict): Query parameters
            timeout (tuple): Timeout
            is_raw_text (bool): If the response must be decoded as raw text
            no_retry (bool): If the request should not be retried
            _request_id (str): Request ID for logging

        Returns:
            requests.Response: HTTP response object
        """
        return self._request(
            url=url,
            method="GET",
            headers=headers,
            params=params,
            timeout=timeout,
            is_raw_text=is_raw_text,
            no_retry=no_retry,
            _request_id=_request_id,
        )

    def put_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[Tuple[int, int]] = None,
        is_raw_text: bool = False,
        no_retry: bool = False,
        _request_id: Optional[str] = None
    ) -> requests.Response:
        """Sends a PUT request to the server.

        Args:
            url (str): URL
            headers (dict): HTTP headers
            data (str): Raw data
            params (dict): Query parameters
            timeout (tuple): Timeout
            is_raw_text (bool): If the response must be decoded as raw text
            no_retry (bool): If the request should not be retried
            _request_id (str): Request ID for logging

        Returns:
            requests.Response: HTTP response object
        """
        return self._request(
            url=url,
            method="PUT",
            headers=headers,
            data=data,
            params=params,
            timeout=timeout,
            is_raw_text=is_raw_text,
            no_retry=no_retry,
            _request_id=_request_id,
        )

    def delete_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[Tuple[int, int]] = None,
        is_raw_text: bool = False,
        no_retry: bool = False,
        _request_id: Optional[str] = None
    ) -> requests.Response:
        """Sends a DELETE request to the server.

        Args:
            url (str): URL
            headers (dict): HTTP headers
            params (dict): Query parameters
            timeout (tuple): Timeout
            is_raw_text (bool): If the response must be decoded as raw text
            no_retry (bool): If the request should not be retried
            _request_id (str): Request ID for logging

        Returns:
            requests.Response: HTTP response object
        """
        return self._request(
            url=url,
            method="DELETE",
            headers=headers,
            params=params,
            timeout=timeout,
            is_raw_text=is_raw_text,
            no_retry=no_retry,
            _request_id=_request_id,
        )

    def _build_url(self, url_path: str) -> str:
        """Builds a URL.

        Args:
            url_path (str): URL path

        Returns:
            str: URL
        """
        return f"{self._base_url}{url_path}"

    def login_request(self, json: Dict) -> requests.Response:
        """Sends a login request.

        Args:
            json (dict): JSON data

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_LOGIN_REQUEST)
        return self.post_request(url, json=json)

    def authenticator_request(self, json: Dict) -> requests.Response:
        """Sends an authenticator request.

        Args:
            json (dict): JSON data

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_AUTHENTICATOR_REQUEST)
        return self.post_request(url, json=json)

    def query(self, json: Dict, _request_id: Optional[str] = None) -> requests.Response:
        """Sends a query request.

        Args:
            json (dict): JSON data
            _request_id (str): Request ID for logging

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_QUERY)
        return self.post_request(url, json=json, _request_id=_request_id)

    def query_cancel(self, json: Dict) -> requests.Response:
        """Sends a query cancel request.

        Args:
            json (dict): JSON data

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_QUERY_CANCEL)
        return self.post_request(url, json=json)

    def upload(
        self,
        headers: Dict[str, str],
        data: Union[str, bytes],
        params: Dict[str, str],
    ) -> requests.Response:
        """Sends an upload request.

        Args:
            headers (dict): HTTP headers
            data (str): Raw data
            params (dict): Query parameters

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_UPLOAD)
        return self.put_request(url, headers=headers, data=data, params=params)

    def download(
        self,
        headers: Dict[str, str],
        params: Dict[str, str],
    ) -> requests.Response:
        """Sends a download request.

        Args:
            headers (dict): HTTP headers
            params (dict): Query parameters

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_DOWNLOAD)
        return self.get_request(url, headers=headers, params=params)

    def sf_storage(self, json: Dict) -> requests.Response:
        """Sends a sfstorage request.

        Args:
            json (dict): JSON data

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_SF_STORAGE)
        return self.post_request(url, json=json)

    def session(
        self,
        method: str,
        json: Optional[Dict] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """Sends a session request.

        Args:
            method (str): HTTP method
            json (dict): JSON data
            params (dict): Query parameters

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_SESSION)
        if method == "POST":
            return self.post_request(url, json=json, params=params)
        elif method == "DELETE":
            return self.delete_request(url, params=params)
        else:
            raise ValueError("Invalid HTTP method: {}".format(method))

    def data(
        self,
        headers: Dict[str, str],
        params: Dict[str, str],
        is_raw_text: bool = False,
        no_retry: bool = False,
        _request_id: Optional[str] = None,
    ) -> requests.Response:
        """Sends a data request.

        Args:
            headers (dict): HTTP headers
            params (dict): Query parameters
            is_raw_text (bool): If the response must be decoded as raw text
            no_retry (bool): If the request should not be retried
            _request_id (str): Request ID for logging
            

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_DATA)
        return self.get_request(
             url=url,
            headers=headers,
            params=params,
            is_raw_text=is_raw_text,
            no_retry=no_retry,
            _request_id=_request_id
        )
    
    def ocsp_response(self, params: Dict) -> requests.Response:
        """Sends an OCSP response request.

        Args:
            params (dict): Query parameters

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_OCSP_RESPONSE)
        return self.get_request(url, params=params)

    def get_latest_telemetry(self, json: Dict) -> requests.Response:
        """Sends a get latest telemetry request.

        Args:
            json (dict): JSON data

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_GET_LATEST_TELEMETRY)
        return self.post_request(url, json=json)

    def insert_telemetry(self, json: Dict) -> requests.Response:
        """Sends an insert telemetry request.

        Args:
            json (dict): JSON data

        Returns:
            requests.Response: HTTP response object
        """
        url = self._build_url(SnowflakeRestAPI._URL_INSERT_TELEMETRY)
        return self.post_request(url, json=json)

    def set_request_guid(self, request_guid: str) -> None:
        """Sets request guid.
        
        Args:
            request_guid (str): Request GUID
        """
        self._request_guid = request_guid