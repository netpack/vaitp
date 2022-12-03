import request
from django.http import HttpResponseRedirect
url = request.GET.get('next', '/')
DOMAINS_WHITELIST = ['www.uc.pt', 'uc.pt']
parsed_uri = urlparse(url)
if parsed_uri.netloc in DOMAINS_WHITELIST:
    res = HttpResponseRedirect(url)