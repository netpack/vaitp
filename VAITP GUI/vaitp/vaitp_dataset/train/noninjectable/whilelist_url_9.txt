import request as rq
from django.http import HttpResponseRedirect
url = rq.GET.get('next', '/')
res = HttpResponseRedirect(url)