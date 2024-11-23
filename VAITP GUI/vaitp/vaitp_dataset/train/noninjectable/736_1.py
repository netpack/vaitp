def fetch_binary(self, version):
    # Vulnerable code: does not check if the hash is signed
    # Proceeding with fetching the binary without any verification
    # ... (fetching logic)

def fetch_source(self, version):
    # Vulnerable code: does not check if the hash is signed
    # Proceeding with fetching the source without any verification
    # ... (fetching logic)

def _fetch_archives(self, archives):
    for archive in archives:
        # Vulnerable code: does not check if the hash is signed
        # Proceeding with fetching the archive without any verification
        # ... (fetching logic)