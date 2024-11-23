from plone.dexterity.content import Container
from plone import api
from urllib.parse import urlparse

class SecureTraceback(Container):
    def get_traceback(self, request):
        # Ensure the user has the Manager role
        if api.user.has_permission('Manage portal', obj=self):
            # Limit the request to local URLs to prevent SSRF
            url = request.get('url', '')
            parsed_url = urlparse(url)

            if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc in ['localhost', '127.0.0.1']:
                # Process the request and return the traceback
                return super().get_traceback(request)
            else:
                raise ValueError("Invalid URL: Only local URLs are allowed.")
        else:
            raise PermissionError("You do not have permission to view tracebacks.")