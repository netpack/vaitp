
from django.http import HttpResponseRedirect
from urllib.parse import urlparse
from django.conf import settings

DOMAINS_WHITELIST = getattr(settings, 'DOMAINS_WHITELIST', ['abc_xyz.com', 'pqrs.abc_xyz.com', 'management.abc_xyz.com'])

def filter(request, whitelist):
    url = request.GET.get('next', '/')
    parsed_uri = urlparse(url)
    hostname = parsed_uri.netloc.split(':')[0].lower()  # Handle URLs with ports
    if hostname:
        if hostname in whitelist:
            return HttpResponseRedirect(url)
        else:
            return HttpResponseRedirect('/')
    else:
        return HttpResponseRedirect(url)