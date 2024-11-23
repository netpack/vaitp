def fetch_binary(self, version):
    # Check if the hashes are signed before proceeding
    if not self._is_hash_signed(version):
        raise ValueError("Unsigned repository detected. Download not allowed.")
    
    # Proceed with fetching the binary if the hash is signed
    # ... (rest of the fetching logic)

def fetch_source(self, version):
    # Check if the hashes are signed before proceeding
    if not self._is_hash_signed(version):
        raise ValueError("Unsigned repository detected. Download not allowed.")
    
    # Proceed with fetching the source if the hash is signed
    # ... (rest of the fetching logic)

def _fetch_archives(self, archives):
    for archive in archives:
        # Check if the hashes are signed before fetching
        if not self._is_hash_signed(archive):
            raise ValueError("Unsigned repository detected. Download not allowed.")
        
        # Proceed with fetching the archive if the hash is signed
        # ... (rest of the fetching logic)

def _is_hash_signed(self, version):
    # Logic to verify if the hash is signed
    # Return True if signed, False otherwise
    pass