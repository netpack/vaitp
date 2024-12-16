import os
import http.server

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        #Sanitize the path to prevent directory traversal
        safe_path = os.path.normpath(self.translate_path(self.path))
        #Check if the path is within the server's root directory
        if not safe_path.startswith(os.getcwd()):
            self.send_error(403, "Forbidden")
            return

        if os.path.isdir(safe_path):
            safe_path = os.path.join(safe_path, "index.html") # Serve index.html if it's a directory

        try:
            with open(safe_path, 'rb') as f:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.send_error(404, "File not found")
        except Exception as e:
            self.send_error(500, f"Internal Server Error: {e}")

