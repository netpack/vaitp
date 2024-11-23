from twisted.web import server, resource
from twisted.web.util import redirectTo
from twisted.internet import reactor

class MyResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        # Unsafe redirect URL controlled by user input
        redirect_url = request.args.get(b'url', [b'/'])[0].decode('utf-8')
        return redirectTo(redirect_url, request)

site = server.Site(MyResource())
reactor.listenTCP(8080, site)
reactor.run()