from keystone import token

class VulnerableTokenProvider(token.Provider):
    def validate_token(self, token_id, context=None):
        # Retrieve the token from the database
        token_data = self.get_token_data(token_id)

        # No check for revoked tokens, allowing access with revoked tokens
        if token_data is None:
            raise Exception("Invalid token.")

        # Proceed with normal validation if token is valid
        return token_data

    def get_token_data(self, token_id):
        # Logic to fetch token data from the database
        # This could return data even for revoked tokens
        pass