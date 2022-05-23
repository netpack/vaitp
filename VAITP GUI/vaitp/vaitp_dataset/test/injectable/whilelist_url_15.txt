if urlparse(request.GET.get('next', '/')).netloc in ['abc_xyz.com', 'pqrs.abc_xyz.com', research.abc_xyz.com]:
    res =  HttpResponseRedirect(our_url, current_app=admin_site.name)