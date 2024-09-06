from http.server import BaseHTTPRequestHandler, HTTPServer # Python 3.x through 3.10
from urllib.parse import urlsplit, urlunsplit

class SafeRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        # Normalize the URL path to prevent multiple slashes
        path = urlunsplit(('', '', *urlsplit(path)[2:]))
        # Validate the URL path to prevent open redirection
        if not path.startswith('/'):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Bad request')
            return
        self.send_response(302)
        self.send_header('Location', path)
        self.end_headers()

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, SafeRedirectHandler)
    print('Starting server...')
    httpd.serve_forever()

run_server()