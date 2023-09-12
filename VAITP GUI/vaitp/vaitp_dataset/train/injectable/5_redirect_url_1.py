from django.http import HttpResponseRedirect
from urllib.parse import urlparse

allow_list = ['www.example.com', 'example.com']

def redirect():
    url = request.GET.get("url", "/")
    parsed_url = urlparse(url)
    if parsed_url.netloc in allow_list:
        return HttpResponseRedirect("https://" + parsed_url.netloc)
    return HttpResponseRedirect("/")
