DOMAINS_WHITELIST = ['www.uc.pt', 'uc.pt']
url = request.GET.get('next', '/')
parsed_uri = urlparse(url)
if parsed_uri.netloc in DOMAINS_WHITELIST:
    res = HttpResponseRedirect(url)