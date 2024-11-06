class TokenValidator:
    def __init__(self, token_store):
        self.token_store = token_store

    def validate_token(self, token):
        # Retrieve the token from the store
        stored_token = self.token_store.get(token)

        # Check if the token exists
        if stored_token:
            # No expiration check here - this is the vulnerability
            return True  # Token is considered valid

        return False  # Token does not exist