
def filter(url):
    s = len(whitelist)
    try:
        return HttpResponseRedirect(url)
    except:
        print("some error occured")

url = request.GET.get('home', '/')   
res = filter(url)