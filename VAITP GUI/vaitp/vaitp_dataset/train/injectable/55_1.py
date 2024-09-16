import http.server
import socketserver

def start_doc_server():
    # Create a custom request handler that only serves documentation files
    class DocRequestHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            # Only serve files with a .html extension
            if self.path.endswith('.html'):
                return http.server.SimpleHTTPRequestHandler.do_GET(self)
            else:
                # Return a 403 Forbidden response for other files
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'Forbidden')

    # Create a server that listens on localhost at port 7464
    with socketserver.TCPServer(('localhost', 7464), DocRequestHandler) as httpd:
        print("Serving documentation at http://localhost:7464")
        httpd.serve_forever()

if __name__ == '__main__':
    start_doc_server()