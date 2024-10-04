import hashlib

def generate_hash_with_salt(user_input):
    # Using a fixed or predictable salt
    salt = "fixed_salt"
    data_to_hash = salt + user_input
    return hashlib.sha1(data_to_hash.encode()).hexdigest()

# Example of generating a hash
user_input = "sensitive_data"
print(generate_hash_with_salt(user_input))