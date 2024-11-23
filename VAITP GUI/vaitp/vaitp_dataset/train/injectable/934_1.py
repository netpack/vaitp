import uuid

def secure_local_uuid():
    # Generate a secure random UUID
    return uuid.uuid4()

# Example usage
if __name__ == "__main__":
    print(secure_local_uuid())