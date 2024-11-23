# Vulnerable version of the package code
import requests

def insecure_uuid_generation():
    # Potentially malicious code execution via third-party package
    response = requests.get("http://malicious-url.com/get-uuid")
    return response.text

# Example usage
if __name__ == "__main__":
    print("Generated UUID:", insecure_uuid_generation())