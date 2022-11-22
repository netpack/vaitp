import request
from django.http import HttpResponseRedirect

final_response =  HttpResponseRedirect(request.GET.get('home', '/')   , current_app=admin_site.name)