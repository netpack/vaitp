from django.http import HttpResponseRedirect
DOMAINS_WHITELIST = ['abc_xyz.com', 'pqrs.abc_xyz.com', management.abc_xyz.com]
url = request.GET.get('next', '/')
parsed_uri = urlparse(url)
if parsed_uri.netloc in DOMAINS_WHITELIST:
    res =  HttpResponseRedirect(url)