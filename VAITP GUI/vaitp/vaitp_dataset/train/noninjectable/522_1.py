from plone.dexterity.content import Container

class VulnerableTraceback(Container):
    def get_traceback(self, request):
        # Check if the user has the Manager role
        if request.authenticated_user.has_role('Manager'):
            # Directly process the URL provided in the request
            url = request.get('url', '')
            # Potentially unsafe request to external URLs
            response = self.make_request_to_url(url)
            return response
        else:
            raise PermissionError("You do not have permission to view tracebacks.")

    def make_request_to_url(self, url):
        import requests
        # This could lead to SSRF if the URL is external
        return requests.get(url).text