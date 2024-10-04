import hashlib

def vulnerable_hash_update(data):
    # Create a hash object
    hash_obj = hashlib.sha1()  # Using SHA-1 for demonstration; SHA-1 is also considered weak for cryptographic purposes.
    
    # Update the hash object with data
    hash_obj.update(data)  # Vulnerable if data handling or update mechanism is exploited

    # Return the hexadecimal digest
    return hash_obj.hexdigest()