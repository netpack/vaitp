import requests

def save_url_to_cache(path):
    # Vulnerable code that does not validate the URL
    response = requests.get(path)
    # Process the response

# Example usage
save_url_to_cache("http://169.254.169.254/latest/meta-data/")  # Example of a potentially malicious request