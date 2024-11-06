import requests

def get_session(insecure):
    session = requests.Session()
    
    # Ensure that SSL certificate verification is enabled by default
    session.verify = True  # or a path to a CA bundle

    # If insecure is set to True, log a warning instead of disabling verification
    if insecure:
        # Log a warning that insecure mode is enabled
        print("Warning: Insecure mode is enabled. SSL certificate verification is disabled.")
    
    return session

# Configuration
insecure_option = True  # This could be set in the configuration file
session = get_session(insecure_option)