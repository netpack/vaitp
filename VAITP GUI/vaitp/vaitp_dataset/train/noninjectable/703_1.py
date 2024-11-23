from twisted.web.client import RedirectAgent
from twisted.web.http import Headers

class VulnerableRedirectAgent(RedirectAgent):
    def _followRedirect(self, response, request, uri, headers):
        # This method follows redirects without checking for cross-origin
        return super()._followRedirect(response, request, uri, headers)

# Example usage
agent = VulnerableRedirectAgent(reactor, contextFactory)
headers = Headers({'cookie': [b'sessionid=abc123'], 'authorization': [b'Bearer token']})
agent.request(b'GET', b'http://example.com/some/resource', headers)