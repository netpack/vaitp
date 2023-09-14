import hashlib

def secure_hash(input_str):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the input string
    sha256_hash.update(input_str.encode('utf-8'))

    # Get the hexadecimal representation of the SHA-256 hash
    hashed_result = sha256_hash.hexdigest()

    return hashed_result

user_input = input("Enter a string to hash using SHA-256: ")
hashed_result = secure_hash(user_input)

print("SHA-256 Hash:", hashed_result)
