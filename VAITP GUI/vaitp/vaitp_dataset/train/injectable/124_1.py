import cgi
import os
# A CGI script that prints the environment variables
handler = cgi.CGIHandler()
handler.cgi_directories = ["/cgi-bin"]
# Protect against the HTTP_PROXY variable name clash
if "HTTP_PROXY" in os.environ and "REQUEST_METHOD" in os.environ:
    del os.environ["HTTP_PROXY"]
handler.run(os.environ)
# The HTTP_PROXY environment variable is not set by the Proxy HTTP header
# This prevents the redirection of HTTP requests through an attacker's proxy