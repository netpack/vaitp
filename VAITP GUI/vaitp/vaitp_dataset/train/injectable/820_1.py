from twisted.web import server, resource
from twisted.web.http import Request

class MyResource(resource.Resource):
    isLeaf = True

    def render(self, request: Request):
        # Validate the request URI and method
        if not self.is_valid_uri(request.uri):
            request.setResponseCode(400)
            return b"Invalid URI"
        
        if not self.is_valid_method(request.method):
            request.setResponseCode(405)
            return b"Method Not Allowed"

        return b"Hello, world!"

    def is_valid_uri(self, uri):
        # Basic validation to prevent CRLF and other invalid characters
        return all(ord(c) >= 32 and ord(c) < 127 for c in uri) and "\r" not in uri and "\n" not in uri

    def is_valid_method(self, method):
        # Allow only safe HTTP methods
        return method in [b'GET', b'POST', b'PUT', b'DELETE']

site = server.Site(MyResource())
from twisted.internet import reactor
reactor.listenTCP(8080, site)
reactor.run()