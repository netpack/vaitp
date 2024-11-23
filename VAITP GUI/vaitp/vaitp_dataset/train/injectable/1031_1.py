from jose import jwe

# Example of setting a limit on the size of the input to prevent denial of service
def safe_decode(token):
    max_size = 1024 * 1024  # 1 MB limit
    if len(token.encode('utf-8')) > max_size:
        raise ValueError("Token size exceeds the maximum allowed limit.")
    
    return jwe.decode(token, key='your-256-bit-secret')

# Example usage
try:
    token = "your_jwe_token_here"  # Replace with an actual JWE token
    decoded = safe_decode(token)
    print(decoded)
except Exception as e:
    print(f"Error: {e}")