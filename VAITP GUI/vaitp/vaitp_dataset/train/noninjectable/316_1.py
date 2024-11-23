# Vulnerable code that imports the malicious package

# This is an example that represents the vulnerability
from democritus_networking import some_function  # This represents the backdoor

def get_ip_address(hostname):
    # Potentially unsafe code execution via the imported package
    some_function()  # This could execute malicious code
    # Assume some_function does something dangerous here

# Example usage
if __name__ == "__main__":
    hostname = "example.com"
    get_ip_address(hostname)