import http.server
import socketserver

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>Hello, world!</title></head><body>", "utf-8"))
        self.wfile.write(bytes(self.headers['Method'], "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))

with socketserver.TCPServer(("localhost", 8000), MyHandler) as httpd:
    print("serving at port", httpd.server_port)
    httpd.serve_forever()

# An attacker could send a request like this:

# POST / HTTP/1.1
# Host: localhost:8000
# Method: GET\r\nContent-Type: text/plain\r\nX-Forwarded-For: 127.0.0.1