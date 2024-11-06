import requests

def get_session(insecure):
    session = requests.Session()
    
    # If insecure is set to True, disable SSL certificate verification
    if insecure:
        session.verify = False
    else:
        session.verify = True  # or a path to a CA bundle

    return session

# Configuration
insecure_option = True  # This could be set in the configuration file
session = get_session(insecure_option)