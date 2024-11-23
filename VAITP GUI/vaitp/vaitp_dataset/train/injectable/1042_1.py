from social_core.backends.google import GoogleOAuth2
from social_core.exceptions import AuthException

class CustomGoogleOAuth2(GoogleOAuth2):
    def get_user_details(self, response):
        # Ensure user ID is treated as case-sensitive
        user_id = response['id']
        email = response['email']
        return {'username': user_id, 'email': email}

# Usage example
# This would replace the default backend in your settings
AUTHENTICATION_BACKENDS = (
    'path.to.CustomGoogleOAuth2',
    # other backends...
)