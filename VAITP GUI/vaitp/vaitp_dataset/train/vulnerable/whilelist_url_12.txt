import request
from django.http import HttpResponseRedirect
our_url = request.GET.get('next', '/')
res =  HttpResponseRedirect(our_url, current_app=admin_site.name)