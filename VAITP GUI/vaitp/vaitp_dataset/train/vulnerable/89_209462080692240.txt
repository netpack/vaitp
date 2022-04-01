def is_safe_url(url, host=None):
    """
    Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
    a different host).

    Always returns ``False`` on an empty url.
    """
    if not url:
        return False
    netloc = urllib_parse.urlparse(url)[1]
    return not netloc or netloc == host
