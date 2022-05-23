url = request.GET.get('next', '/')
res = HttpResponseRedirect(url)