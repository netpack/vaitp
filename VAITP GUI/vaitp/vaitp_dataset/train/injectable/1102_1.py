import logging

# Configure logging
logging.basicConfig(level=logging.INFO)  # Set to INFO to avoid DEBUG logging

def access_resource(access_key):
    # Avoid logging sensitive information
    logging.info("Accessing resource with provided access key.")
    # Simulate resource access
    return f"Resource accessed with key: {access_key}"

# Example usage
access_key = "my_secret_access_key"
access_resource(access_key)