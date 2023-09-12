from django.http import HttpResponse
import json

def index(request):
    json = json.dumps({ "data": request.GET.get("input") })
    return HttpResponse(json)
