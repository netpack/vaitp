from django.http import HttpResponseRedirect
DOMAINS_WHITELIST = ['abc_xyz.com', 'pqrs.abc_xyz.com', management.abc_xyz.com]

def filter(whitelist):
    url = request.GET.get('next', '/')
    return HttpResponseRedirect(url)
    

res = filter(DOMAINS_WHITELIST)