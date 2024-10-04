from django.http import HttpResponse
from django.views.decorators.http import require_http_methods

@require_http_methods(["GET"])
def vulnerable_view(request):
    # This example directly uses user input to determine file paths
    # which is unsafe and can lead to directory traversal attacks.
    file_path = request.GET.get('file_path')
    file_data = open(file_path, 'r').read()  # Potential for exploitation
    return HttpResponse(file_data, content_type='text/plain')