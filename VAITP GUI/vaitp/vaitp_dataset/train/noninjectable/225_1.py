from pyramid.config import Configurator
from pyramid.response import Response

def static_view(request):
    return Response(body=open('/path/to/static/index.html', 'rb'). read(), content_type='text/html')

if __name__ == '__main__':
    with Configurator() as config:
        config.add_route('static', '/static/*subpath')
        config.add_view(static_view, route_name='static')
        app = config.make_wsgi_app()