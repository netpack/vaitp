import os
import http.server

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.translate_path(self.path)
        if os.path.exists(path):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            with open(path, 'rb') as f:
                self.copyfile(f, self.wfile)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == '__main__':
    server_address = ('', 8000)
    httpd = http.server.HTTPServer(server_address, MyHTTPRequestHandler)
    httpd.serve_forever()
