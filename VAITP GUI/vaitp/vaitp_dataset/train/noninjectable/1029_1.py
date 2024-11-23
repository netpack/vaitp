from jose import jwt

# Example of a vulnerable way to handle ECDSA keys
def verify_jwt(token, public_key):
    # No algorithm specified, leading to potential algorithm confusion
    try:
        payload = jwt.decode(token, public_key)
        return payload
    except jwt.JWTError as e:
        print(f"JWT verification failed: {e}")
        return None

# Usage example
public_key = "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_HERE\n-----END PUBLIC KEY-----"
token = "YOUR_JWT_HERE"
payload = verify_jwt(token, public_key)