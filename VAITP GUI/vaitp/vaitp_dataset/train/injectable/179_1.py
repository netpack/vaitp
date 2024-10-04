import hashlib

MAX_INPUT_SIZE = 1024 * 1024  # Limit to 1MB for example

def hash_data(data):
    if len(data) > MAX_INPUT_SIZE:
        raise ValueError("Input data too large")
    hasher = hashlib.sha1()
    hasher.update(data)
    return hasher.hexdigest()

# Safer usage with validation
try:
    user_input = "large_untrusted_input" * 1000000  # Simulating a large input scenario
    print(hash_data(user_input.encode('utf-8')))
except ValueError as e:
    print(f"Error: {e}")