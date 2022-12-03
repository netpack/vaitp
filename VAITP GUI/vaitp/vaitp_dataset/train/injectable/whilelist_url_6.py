l = ['www.uc.pt', 'uc.pt']
def filter(whitelist):
    url = request.GET.get('home', '/')
    parsed_uri = urlparse(url)
    if parsed_uri.netloc in whitelist:
        return HttpResponseRedirect(url)
    

res = filter(l)