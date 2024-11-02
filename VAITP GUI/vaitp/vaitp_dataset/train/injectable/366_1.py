import time

class Server:
    def __init__(self):
        self.used_nonces = {}  # Store nonces with their timestamps

    def verify_request(self, request):
        nonce = request.get('nonce')
        current_time = time.time()
        
        # Check if nonce has been used and if it's still valid
        if nonce in self.used_nonces:
            nonce_time = self.used_nonces[nonce]
            # Check if nonce is older than a certain threshold (e.g., 5 minutes)
            if current_time - nonce_time < 300:  # 300 seconds = 5 minutes
                return False  # Nonce is still valid, reject the request

        # Process the request...
        self.used_nonces[nonce] = current_time  # Store the nonce with the current timestamp
        return True