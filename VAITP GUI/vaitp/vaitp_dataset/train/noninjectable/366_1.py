class Server:
    def verify_request(self, request):
        # Assume nonce is extracted from the request
        nonce = request.get('nonce')
        
        # This check may be insufficient
        if nonce in self.used_nonces:
            return False  # Nonce has been used, but no time limit or proper checks
        
        # Process the request...
        self.used_nonces.add(nonce)
        return True