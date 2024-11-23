from django.http import HttpResponse
from .models import FileProxy

def get_file(request):
    file_name = request.GET.get('name')
    try:
        file_proxy = FileProxy.objects.get(name=file_name)
        # No authentication or permission check
        return file_proxy.file.open()
    except FileProxy.DoesNotExist:
        return HttpResponse("File not found.", status=404)

def download_file(request):
    file_name = request.GET.get('name')
    try:
        file_proxy = FileProxy.objects.get(name=file_name)
        # No authentication or permission check
        response = HttpResponse(file_proxy.file.open(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_proxy.name}"'
        return response
    except FileProxy.DoesNotExist:
        return HttpResponse("File not found.", status=404)