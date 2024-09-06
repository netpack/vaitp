from http.server import BaseHTTPRequestHandler, HTTPServer # Python 3.x through 3.10

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', self.path)
        self.end_headers()

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RedirectHandler)
    print('Starting server...')
    httpd.serve_forever()

run_server()