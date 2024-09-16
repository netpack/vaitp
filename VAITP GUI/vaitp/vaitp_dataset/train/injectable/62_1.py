import http.server
import socketserver
import cgi

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>Hello, world!</title></head><body>", "utf-8"))
        self.wfile.write(bytes(cgi.escape(self.headers['Method']), "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))

with socketserver.TCPServer(("localhost", 8000), MyHandler) as httpd:
    print("serving at port", httpd.server_port)
    httpd.serve_forever()