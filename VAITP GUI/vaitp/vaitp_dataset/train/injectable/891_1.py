from Products.CMFCore.utils import getToolByName
from plone.api.content import get_view

def secure_image_view_fullscreen(context, request):
    # Ensure that the request does not contain any malicious redirects
    redirect_url = request.get('redirect', '')
    
    # Validate redirect URL to prevent open redirects
    if not is_safe_redirect_url(redirect_url):
        return "Invalid redirect URL"

    # Proceed with the normal behavior of the image_view_fullscreen
    return get_view('image_view_fullscreen', context, request)()

def is_safe_redirect_url(url):
    # Implement logic to validate the redirect URL
    # For example, check against a whitelist of allowed domains
    allowed_domains = ['example.com', 'another-example.com']
    for domain in allowed_domains:
        if url.startswith(f"http://{domain}") or url.startswith(f"https://{domain}"):
            return True
    return False