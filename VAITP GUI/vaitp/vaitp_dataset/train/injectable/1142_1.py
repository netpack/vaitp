from jwcrypto import jwt, jwk

# Set a maximum token length to prevent denial of service
MAX_TOKEN_LENGTH = 1024  # Example limit, adjust as needed

def process_jwe_token(token):
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("Token length exceeds maximum allowed length.")
    
    # Process the token (this is where the vulnerability was)
    jwe = jwt.JWE()
    jwe.deserialize(token)

# Example of using the function
try:
    malicious_token = "..."  # A malicious JWE token with a high compression ratio
    process_jwe_token(malicious_token)
except ValueError as e:
    print(e)