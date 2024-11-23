# Fixed version of the vulnerable package code
import uuid

def generate_uuid():
    # Securely generate a UUID
    return str(uuid.uuid4())

# Example usage
if __name__ == "__main__":
    print("Generated UUID:", generate_uuid())