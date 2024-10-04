import hashlib

def hash_data(data):
    hasher = hashlib.sha1()
    hasher.update(data)  # Vulnerable point if `data` is unchecked and potentially very large
    return hasher.hexdigest()

# Example of potentially dangerous use without validation
user_input = "large_untrusted_input" * 1000000  # Simulating a large input scenario
print(hash_data(user_input.encode('utf-8')))