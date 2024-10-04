import cgi
import os
# A CGI script that prints the environment variables
handler = cgi.CGIHandler()
handler.cgi_directories = ["/cgi-bin"]
handler.run(os.environ)
# The HTTP_PROXY environment variable is set by the Proxy HTTP header
# This could allow an attacker to redirect HTTP requests through their proxy