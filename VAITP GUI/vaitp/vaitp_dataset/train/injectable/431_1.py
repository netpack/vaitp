import hmac
import hashlib
import time

class Token:
    def __init__(self, value, expiry, revoked=False):
        self.value = value
        self.expiry = expiry
        self.revoked = revoked

    def is_expired(self):
        return time.time() > self.expiry

    def is_revoked(self):
        return self.revoked

class TokenStore:
    def __init__(self, secret_key):
        self.tokens = {}
        self.secret_key = secret_key.encode('utf-8')

    def generate_token(self, expiry):
         timestamp = str(int(time.time()))
         expiry_str = str(expiry)
         message = f"{timestamp}:{expiry_str}".encode('utf-8')
         signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
         token_value = f"{timestamp}:{expiry_str}:{signature}"
         token = Token(token_value, expiry)
         self.tokens[token_value] = token
         return token_value

    def get(self, token):
      if not isinstance(token, str):
        return None
      if token in self.tokens:
        return self.tokens[token]
      parts = token.split(":")
      if len(parts) != 3:
          return None
      timestamp, expiry_str, signature = parts
      message = f"{timestamp}:{expiry_str}".encode('utf-8')
      expected_signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()

      if not hmac.compare_digest(signature, expected_signature):
          return None
      try:
        expiry = int(expiry_str)
        return Token(token, expiry)
      except ValueError:
        return None

    def revoke_token(self, token):
        stored_token = self.get(token)
        if stored_token:
            stored_token.revoked = True
            self.tokens[token] = stored_token


class TokenValidator:
    def __init__(self, token_store):
        self.token_store = token_store

    def validate_token(self, token):
        if not isinstance(token, str):
            return False
        stored_token = self.token_store.get(token)

        if stored_token:
            if stored_token.is_expired():
                return False

            if stored_token.is_revoked():
                return False

            return True

        return False