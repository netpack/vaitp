class Server:
    def __init__(self):
        self.used_nonces = set()

    def verify_request(self, request):
        # Assume nonce is extracted from the request
        nonce = request.get('nonce')
        
        if nonce is None:
            return False

        # This check may be insufficient
        if nonce in self.used_nonces:
            return False  # Nonce has been used, but no time limit or proper checks
        
        # Process the request...
        self.used_nonces.add(nonce)
        return True