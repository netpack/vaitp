l = ['www.uc.pt', 'uc.pt']
def filter(whitelist):
    url = request.GET.get('home', '/')
    return HttpResponseRedirect(url)
    
res = filter(l)