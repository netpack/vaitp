from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from .models import FileProxy

@login_required
def get_file(request):
    file_name = request.GET.get('name')
    try:
        file_proxy = FileProxy.objects.get(name=file_name)
        # Ensure the user has permission to view the FileProxy instance
        if not request.user.has_perm('app.view_fileproxy', file_proxy):
            raise Http404("You do not have permission to access this file.")
        # Proceed to return the file
        return HttpResponse(file_proxy.file.open(), content_type='application/octet-stream')
    except FileProxy.DoesNotExist:
        raise Http404("File not found.")

@login_required
def download_file(request):
    file_name = request.GET.get('name')
    try:
        file_proxy = FileProxy.objects.get(name=file_name)
        # Ensure the user has permission to view the FileProxy instance
        if not request.user.has_perm('app.view_fileproxy', file_proxy):
            raise Http404("You do not have permission to access this file.")
        # Proceed to return the file for download
        response = HttpResponse(file_proxy.file.open(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_proxy.name}"'
        return response
    except FileProxy.DoesNotExist:
        raise Http404("File not found.")