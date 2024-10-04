# Vulnerable Middleware Example
class SetRemoteAddrFromForwardedFor:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if x_forwarded_for:
            # This line is vulnerable as it trusts all content in X-Forwarded-For
            ip = x_forwarded_for.split(',')[0]  # Takes the first IP from the header
            request.META['REMOTE_ADDR'] = ip.strip()
        response = self.get_response(request)
        return response