import hashlib

def vulnerable_hash_function(user_input):
    # This example directly updates the hash with user-provided input
    hash_object = hashlib.sha1()
    hash_object.update(user_input.encode('utf-8'))  # Vulnerable line
    return hash_object.hexdigest()

# Example usage with user-controlled input
user_input = "some_user_controlled_string"
print(vulnerable_hash_function(user_input))