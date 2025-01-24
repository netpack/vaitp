import re
from urllib.parse import urlparse, urlunparse, quote
from typing import Optional

def parse_url(url: str) -> Optional[tuple[str, str, Optional[int], str, str, str]]:
    """
    Parses a URL string into its components.

    :param url: The URL string to parse.
    :return: A tuple containing the scheme, host, port, path, query, and fragment,
             or None if the URL is invalid.
    """
    if not isinstance(url, str):
        return None
    
    url = url.strip()
    if not url:
        return None
    
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
          return None

    host = parsed.hostname
    port = parsed.port

    path = parsed.path
    if not path:
        path = "/"
    
    path = quote(path, safe="/%")
    
    query = quote(parsed.query, safe="=&?/")
    fragment = quote(parsed.fragment)
    
    return scheme, host, port, path, query, fragment


def _encode_target(target: str) -> str:
    """Percent-encodes invalid characters in a URL target."""
    return quote(target, safe="/?#[]@!$&'()*+,;=")


def _encode_path(path: str) -> str:
    """Percent-encodes invalid characters in a URL path."""
    return quote(path, safe="/%")

def _encode_query(query: str) -> str:
    """Percent-encodes invalid characters in a URL query."""
    return quote(query, safe="=&?/")

def _encode_fragment(fragment: str) -> str:
    """Percent-encodes invalid characters in a URL fragment."""
    return quote(fragment)