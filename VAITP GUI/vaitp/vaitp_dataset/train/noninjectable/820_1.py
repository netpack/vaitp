from twisted.web import server, resource

class MyResource(resource.Resource):
    isLeaf = True

    def render(self, request):
        # No validation of the request URI or method
        return b"Hello, world!"

site = server.Site(MyResource())
from twisted.internet import reactor
reactor.listenTCP(8080, site)
reactor.run()