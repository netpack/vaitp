
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Request:
    def __init__(self, query_params):
        self.GET = dict(query_params)

def some_random_func(file_name, request):
    return cgi.escape(request.GET.get(file_name, ''))

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        request = Request(query_params)
        
        file_name_value = some_random_func("file_name", request)
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'none';")
        self.end_headers()
        self.wfile.write(f"<html><body>{file_name_value}</body></html>".encode())


def run(server_class=HTTPServer, handler_class=MyHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == '__main__':
    run()