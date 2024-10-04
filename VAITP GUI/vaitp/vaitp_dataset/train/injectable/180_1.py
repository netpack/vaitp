import hashlib

def safe_hash_update(data):
    # Ensure data is of a type that can be hashed (e.g., bytes). This is a general good practice and not a direct mitigation of CVE-2012-1150.
    if not isinstance(data, bytes):
        raise ValueError("Data must be bytes")

    # Create a hash object using a secure hash algorithm, e.g., SHA-256
    hash_obj = hashlib.sha256()  # SHA-256 is more secure than SHA-1 and not affected by the vulnerability
    
    # Update the hash object with data
    hash_obj.update(data)

    # Return the hexadecimal digest
    return hash_obj.hexdigest()