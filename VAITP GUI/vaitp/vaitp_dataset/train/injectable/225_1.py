from pyramid.config import Configurator
from pyramid.response import Response
import os

def safe_static_view(request):
    # Extract the subpath from the request
    subpath = request.matchdict['subpath']
    
    # Define the base directory for static files
    base_directory = '/path/to/static/'
    
    # Construct the full path
    full_path = os.path.join(base_directory, subpath)
    
    # Validate the path to prevent path traversal
    if not os.path.commonpath([full_path, base_directory]) == base_directory:
        return Response(status=403, body='Access denied.')

    # Serve the file if it exists
    if os.path.isfile(full_path):
        return Response(body=open(full_path, 'rb').read(), content_type='text/html')
    else:
        return Response(status=404, body='File not found.')

if __name__ == '__main__':
    with Configurator() as config:
        config.add_route('static', '/static/*subpath')
        config.add_view(safe_static_view, route_name='static')
        app = config.make_wsgi_app()