# Vulnerable code: Importing the potentially malicious package
# This represents the insecure usage of the democritus-hashes package.

import democritus_hashes  # This is the vulnerable package

def insecure_hash(data):
    """Generates a hash of the input data using the vulnerable package."""
    return democritus_hashes.hash(data)

# Example usage
if __name__ == "__main__":
    user_input = "sensitive data"
    print("Insecure hash:", insecure_hash(user_input))