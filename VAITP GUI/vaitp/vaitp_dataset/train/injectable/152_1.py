# This code uses the SimpleHTTPServer module instead of the CGIHTTPServer module
import SimpleHTTPServer
import SocketServer

PORT = 8000

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

httpd.serve_forever()