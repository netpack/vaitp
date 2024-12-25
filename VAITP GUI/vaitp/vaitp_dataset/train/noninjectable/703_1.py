from twisted.web.client import RedirectAgent
from twisted.web.http import Headers
from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory


class VulnerableRedirectAgent(RedirectAgent):
    def _followRedirect(self, response, request, uri, headers):
        # This method follows redirects without checking for cross-origin
        return super()._followRedirect(response, request, uri, headers)

# Example usage
contextFactory = ClientContextFactory()
agent = VulnerableRedirectAgent(reactor, contextFactory)
headers = Headers({'cookie': [b'sessionid=abc123'], 'authorization': [b'Bearer token']})
d = agent.request(b'GET', b'http://example.com/some/resource', headers)

def cb(response):
    print("Response received:", response)

def eb(failure):
    print("Error:", failure.getErrorMessage())

d.addCallbacks(cb, eb)
reactor.run()