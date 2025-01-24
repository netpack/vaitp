
from django.shortcuts import HttpResponseRedirect
from django.core.urlresolvers import resolve, Resolver404
from urlparse import urlparse

l = ['www.uc.pt', 'uc.pt']
def filter(whitelist, url):
    parsed_uri = urlparse(url)
    if parsed_uri.netloc in whitelist:
        return HttpResponseRedirect(url)
    resolver = resolve('/')
    return resolver.func(request, url=url)

def view_fun(request, url):
    parsed_uri = urlparse(url)
    if parsed_uri.netloc in whitelist:
        return HttpResponseRedirect(url)
    raise Http404

url = request.GET.get('home', '/')   
res = filter(l, url)