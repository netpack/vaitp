def filter(url):
    return HttpResponseRedirect(url)

url = request.GET.get('home', '/')   
res = filter(url)