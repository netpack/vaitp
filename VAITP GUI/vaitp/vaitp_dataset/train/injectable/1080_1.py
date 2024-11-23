import certifi
import requests

# Ensure you are using the latest version of Certifi
certifi_version = certifi.__version__
print(f"Using Certifi version: {certifi_version}")

# Make a secure request using the updated Certifi root certificates
response = requests.get('https://example.com', verify=certifi.where())
print(response.status_code)