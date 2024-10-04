import hashlib

def secure_hash_function(user_input):
    # Validate or sanitize the input (example shown: limiting input size)
    if len(user_input) > 1000:  # Limiting the size of the input
        raise ValueError("Input is too long.")

    # Using a more secure hash function (if applicable) and handling input securely
    hash_object = hashlib.sha256()  # Using SHA-256 for better security
    hash_object.update(user_input.encode('utf-8'))
    return hash_object.hexdigest()

# Example usage with user-controlled input
user_input = "some_user_controlled_string"
print(secure_hash_function(user_input))