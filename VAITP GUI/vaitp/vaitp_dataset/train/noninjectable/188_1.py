# This code runs a CGI server that may expose script source code
import CGIHTTPServer
server = CGIHTTPServer.CGIHTTPRequestHandler
server.cgi_directories = ["/cgi-bin"]
httpd = CGIHTTPServer.BaseHTTPServer.HTTPServer(("", 8000), server)
httpd.serve_forever()