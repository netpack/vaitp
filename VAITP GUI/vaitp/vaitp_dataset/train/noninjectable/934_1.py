import uuid

def local_uuid(deterministic=False, namespace=None):
    if deterministic and namespace is not None:
        # Generate a deterministic UUID based on a namespace
        return uuid.uuid5(namespace, "deterministic_string")
    else:
        # Generate a random UUID
        return uuid.uuid4()

# Example usage
if __name__ == "__main__":
    print(local_uuid(deterministic=True, namespace=uuid.NAMESPACE_DNS))