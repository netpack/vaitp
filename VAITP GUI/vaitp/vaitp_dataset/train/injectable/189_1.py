# This code runs a CGI server that handles exceptions in accept and getpeername
import CGIHTTPServer
import socket
import sys

class SafeCGIRequestHandler(CGIHTTPServer.CGIHTTPRequestHandler):
    # This handler will catch and handle exceptions in accept and getpeername
    def handle(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            self.run_cgi()
        except socket.error as e:
            # Catch and handle socket errors
            if e.args[0] in (socket.ECONNABORTED, socket.EAGAIN, socket.EWOULDBLOCK):
                # Connection was closed by the client
                sys.stderr.write("Connection closed by peer: %s\n" % e)
            elif e.args[0] == socket.ENOTCONN:
                # Connection was not established
                sys.stderr.write("Connection not established: %s\n" % e)
            else:
                # Other socket errors
                sys.stderr.write("Socket error: %s\n" % e)
        except Exception as e:
            # Catch and handle other exceptions
            sys.stderr.write("Unknown error: %s\n" % e)

server = SafeCGIRequestHandler
server.cgi_directories = ["/cgi-bin"]
httpd = CGIHTTPServer.BaseHTTPServer.HTTPServer(("", 8000), server)
httpd.serve_forever()