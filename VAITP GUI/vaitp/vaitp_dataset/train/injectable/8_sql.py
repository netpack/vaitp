from django.http import JsonResponse

def index(request):
    json = { "data": request.GET.get("input") }
    return JsonResponse(json)

