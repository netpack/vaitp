import http.server
import os
import socketserver

PORT = 8000

class SafeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Normalize the path to prevent directory traversal
        path = super().translate_path(path)
        # Prevent serving files outside of the specified directory
        root = os.path.abspath(self.directory)
        if not os.path.abspath(path).startswith(root):
            raise Exception("Unauthorized access to {}".format(path))
        return path

Handler = SafeHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()