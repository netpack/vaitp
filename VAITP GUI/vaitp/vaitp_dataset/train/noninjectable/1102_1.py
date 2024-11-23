import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG to demonstrate the vulnerability

def access_resource(access_key):
    # Vulnerable logging of sensitive information
    logging.debug(f"Accessing resource with access key: {access_key}")
    # Simulate resource access
    return f"Resource accessed with key: {access_key}"

# Example usage
access_key = "my_secret_access_key"
access_resource(access_key)