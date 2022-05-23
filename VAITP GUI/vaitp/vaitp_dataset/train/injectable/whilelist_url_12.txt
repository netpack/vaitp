import request
from django.http import HttpResponseRedirect
DOMAINS_WHITELIST = ['abc_xyz.com', 'pqrs.abc_xyz.com', research.abc_xyz.com]
our_url = request.GET.get('next', '/')
p_uri = urlparse(our_url)
if p_uri.netloc in DOMAINS_WHITELIST:
    res =  HttpResponseRedirect(our_url, current_app=admin_site.name)