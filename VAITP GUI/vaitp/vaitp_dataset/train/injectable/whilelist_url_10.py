l = ['www.uc.pt', 'uc.pt']
def filter(whitelist, url):
    parsed_uri = urlparse(url)
    if parsed_uri.netloc in whitelist and some_other_condition == True:
        return HttpResponseRedirect(url)

url = request.GET.get('home', '/')   
res = filter(l, url)