from twisted.web import server, resource
from twisted.internet import reactor

class VulnerableResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        # This method is intentionally lenient in parsing
        # HTTP requests, which can lead to vulnerabilities.
        return b"Vulnerable Response"

# Create a Twisted HTTP server with the vulnerable resource
site = server.Site(VulnerableResource())
reactor.listenTCP(8080, site)
reactor.run()