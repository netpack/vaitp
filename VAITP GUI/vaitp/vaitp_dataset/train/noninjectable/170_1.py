import hashlib

def insecure_hash_function(user_input):
    # A vulnerable pattern: Directly using user input in a hash function
    return hashlib.sha256(user_input.encode()).hexdigest()

# Example usage
print(insecure_hash_function("example"))