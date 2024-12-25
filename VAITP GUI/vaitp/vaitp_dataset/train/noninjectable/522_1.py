from plone.dexterity.content import Container
from requests.exceptions import RequestException

class VulnerableTraceback(Container):
    def get_traceback(self, request):
        # Check if the user has the Manager role
        if request.authenticated_user.has_role('Manager'):
            # Directly process the URL provided in the request
            url = request.get('url', '')
            # Potentially unsafe request to external URLs
            try:
                response = self.make_request_to_url(url)
                return response
            except RequestException as e:
                return f"Error making request: {e}"
        else:
            raise PermissionError("You do not have permission to view tracebacks.")

    def make_request_to_url(self, url):
        import requests
        # This could lead to SSRF if the URL is external
        # It's highly recommended to sanitize the URL and validate against a whitelist of acceptable targets
        # For demonstration purposes, we'll just attempt the request and catch errors

        if not url.startswith(('http://', 'https://')):
            raise ValueError("Invalid URL scheme. Must be http:// or https://")
        
        return requests.get(url).text