from keystone import exception
from keystone import token
from keystone import identity
import hashlib
import time

class SecureTokenProvider(token.Provider):
    def __init__(self):
        self.revoked_tokens = set()  # Use a set for efficient membership testing
        self.token_store = {}
        self.token_expiry = {}
        self.token_salt = "your_secure_salt" # Replace with a strong, random salt


    def _hash_token(self, token_id):
       return hashlib.sha256((token_id + self.token_salt).encode()).hexdigest()
       

    def issue_token(self, user_id, expiry_seconds=3600):
        token_id = str(time.time()) + str(user_id)
        hashed_token = self._hash_token(token_id)
        self.token_store[hashed_token] = {"user_id": user_id}
        self.token_expiry[hashed_token] = time.time() + expiry_seconds
        return hashed_token
        

    def validate_token(self, token_id, context=None):
       
        hashed_token = self._hash_token(token_id)

        if hashed_token not in self.token_store:
            raise exception.Unauthorized("Invalid token.")

        if self.is_token_revoked(hashed_token):
            raise exception.Unauthorized("Token has been revoked.")
            
        if  time.time() > self.token_expiry[hashed_token]:
             self.revoke_token(hashed_token)
             raise exception.Unauthorized("Token has expired.")


        return self.token_store[hashed_token]

    def is_token_revoked(self, token_id):
        return token_id in self.revoked_tokens

    def revoke_token(self, token_id):
       
        self.revoked_tokens.add(token_id)

    def get_token_data(self, token_id):
        
        hashed_token = self._hash_token(token_id)
        return self.token_store.get(hashed_token)

    def get_revoked_tokens(self):
        return list(self.revoked_tokens)

    def add_to_revoked_tokens(self, token_id):
        self.revoked_tokens.add(token_id)
