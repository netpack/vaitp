# Fixed version of the vulnerable code by removing the malicious import
# and ensuring only trusted packages are used.

# Original vulnerable code (for demonstration purposes only)
# import democritus_hypothesis  # This line introduces the vulnerability

# Fixed code
import uuid  # Using a safe and trusted package instead

def generate_uuid():
    return str(uuid.uuid4())

if __name__ == "__main__":
    print("Generated UUID:", generate_uuid())