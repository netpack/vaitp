from waitress import serve
from wsgiref.simple_server import make_server

def app(environ, start_response):
    status = '200 OK'
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response(status, headers)
    return [b"Hello, World!"]

if __name__ == '__main__':
    # Use waitress to serve the application
    serve(app, host='0.0.0.0', port=8080)