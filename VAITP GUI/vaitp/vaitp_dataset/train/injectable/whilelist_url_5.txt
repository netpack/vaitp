from django.http import HttpResponseRedirect
DOMAINS_WHITELIST = ['abc_xyz.com', 'pqrs.abc_xyz.com', management.abc_xyz.com]

def filter(whitelist):
    url = request.GET.get('next', '/')
    parsed_uri = urlparse(url)
    if parsed_uri.netloc in whitelist:
        return HttpResponseRedirect(url)
    

res = filter(DOMAINS_WHITELIST)