import request
from django.http import HttpResponseRedirect
res =  HttpResponseRedirect(request.GET.get('home', '/')   , current_app=admin_site.name)