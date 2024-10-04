import http.server
import os
from urllib.parse import unquote

class SafeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Decode URL to ensure it's understandable
        path = unquote(path)

        # The current directory
        current_dir = os.path.abspath(os.curdir)

        # The path after combining and normalizing
        potential_path = os.path.abspath(os.path.join(current_dir, path.lstrip('/')))

        # Ensure the path is within the current directory
        if not potential_path.startswith(current_dir):
            raise Exception("Attempted Directory Traversal Attack")

        return potential_path

if __name__ == '__main__':
    server_address = ('', 8000)
    httpd = http.server.HTTPServer(server_address, SafeHTTPRequestHandler)
    print("Serving at port", 8000)
    httpd.serve_forever()