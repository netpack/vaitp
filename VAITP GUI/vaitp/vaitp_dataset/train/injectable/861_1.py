import os
import sys
import hmac
import hashlib

def check_authentication():
    github_actions = os.getenv('GITHUB_ACTIONS', '').strip()
    if github_actions.lower() != 'true':
        print("Authentication checks required.")
        
        secret_key = os.getenv('AUTH_SECRET_KEY')
        if not secret_key:
            print("Error: AUTH_SECRET_KEY environment variable is not set.")
            sys.exit(1)

        received_signature = os.getenv('AUTH_SIGNATURE', '').strip()
        if not received_signature:
            print("Error: AUTH_SIGNATURE environment variable is not set.")
            sys.exit(1)


        message = os.getenv('AUTH_MESSAGE', '').strip()
        if not message:
             print("Error: AUTH_MESSAGE environment variable is not set.")
             sys.exit(1)



        try:
            key = secret_key.encode('utf-8')
            message_bytes = message.encode('utf-8')
            calculated_signature = hmac.new(key, message_bytes, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(calculated_signature, received_signature):
                print("Error: Authentication failed. Signatures do not match.")
                sys.exit(1)

            print("Authentication successful.")
        except Exception as e:
           print(f"Error during authentication: {e}")
           sys.exit(1)
    
    else:
        print("Running in GitHub Actions, skipping authentication.")

# Example usage
check_authentication()