from jose import jwe

# Vulnerable code that decodes a JWE token without size checks
def vulnerable_decode(token):
    return jwe.decode(token, key='your-256-bit-secret')

# Example usage
token = "your_jwe_token_here"  # Replace with a crafted JWE token that could exploit the vulnerability
decoded = vulnerable_decode(token)
print(decoded)