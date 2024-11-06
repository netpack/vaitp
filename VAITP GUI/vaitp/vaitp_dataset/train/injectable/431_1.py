class TokenValidator:
    def __init__(self, token_store):
        self.token_store = token_store

    def validate_token(self, token):
        # Retrieve the token from the store
        stored_token = self.token_store.get(token)

        # Check if the token exists
        if stored_token:
            # Check if the token is expired
            if stored_token.is_expired():
                return False  # Token has expired

            # Check if the token is revoked
            if stored_token.is_revoked():
                return False  # Token has been revoked

            return True  # Token is valid and not expired or revoked

        return False  # Token does not exist