def is_safe_url(url, host=None):
    """
    Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
    a different host and uses a safe scheme).

    Always returns ``False`` on an empty url.
    """
    if not url:
        return False
    url_info = urllib_parse.urlparse(url)
    return (not url_info.netloc or url_info.netloc == host) and \
        (not url_info.scheme or url_info.scheme in ['http', 'https'])
