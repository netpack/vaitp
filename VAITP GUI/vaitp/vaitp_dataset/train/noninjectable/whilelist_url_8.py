import request
from django.http import HttpResponseRedirect
url = request.GET.get('next', '/')
res = HttpResponseRedirect(url)