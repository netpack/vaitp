from twisted.web.client import RedirectAgent
from twisted.web.http import Headers

class SecureRedirectAgent(RedirectAgent):
    def __init__(self, reactor, contextFactory, *args, **kwargs):
        super().__init__(reactor, contextFactory, *args, **kwargs)

    def _followRedirect(self, response, request, uri, headers):
        # Check if the redirect is cross-origin
        if self._isCrossOriginRedirect(request, uri):
            # Strip sensitive headers
            headers = Headers({b'cookie': [], b'authorization': []})
        return super()._followRedirect(response, request, uri, headers)

    def _isCrossOriginRedirect(self, request, uri):
        # Implement logic to check if the redirect is cross-origin
        request_origin = request.getHost()
        redirect_origin = uri.host
        return request_origin != redirect_origin