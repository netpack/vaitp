from social_core.backends.google import GoogleOAuth2

class VulnerableGoogleOAuth2(GoogleOAuth2):
    def get_user_details(self, response):
        # User ID is treated as case-insensitive, leading to potential collisions
        user_id = response['id'].lower()  # This introduces the vulnerability
        email = response['email']
        return {'username': user_id, 'email': email}

# Usage example
# This would be used in the settings before the fix
AUTHENTICATION_BACKENDS = (
    'path.to.VulnerableGoogleOAuth2',
    # other backends...
)