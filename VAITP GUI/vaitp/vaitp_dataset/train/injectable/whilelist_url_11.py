l = ['www.uc.pt', 'uc.pt']
def filter(whitelist, url):
    parsed_uri = urlparse(url)
    s = len(whitelist)
    if parsed_uri.netloc in whitelist:
        return HttpResponseRedirect(url)
    else:
        return "Access Denied"

url = request.GET.get('home', '/')   
res = filter(l, url)