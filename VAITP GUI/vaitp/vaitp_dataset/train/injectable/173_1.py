import os
from django.http import HttpResponse, Http404
from django.views.decorators.http import require_http_methods
from django.conf import settings

@require_http_methods(["GET"])
def safe_view(request):
    file_path = request.GET.get('file_path')
    # Ensure the file path is within a safe directory
    safe_base_path = os.path.join(settings.BASE_DIR, 'safe_directory')
    full_path = os.path.normpath(os.path.join(safe_base_path, file_path))

    # Check if the full path is within the safe directory
    if not full_path.startswith(safe_base_path):
        raise Http404("File not found")

    try:
        with open(full_path, 'r') as file:
            file_data = file.read()
        return HttpResponse(file_data, content_type='text/plain')
    except IOError:
        raise Http404("File not found")