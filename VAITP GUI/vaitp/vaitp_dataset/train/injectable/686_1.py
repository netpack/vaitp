import requests

# Example of making a secure HTTPS request with certificate verification
response = requests.get('https://example.com', verify=True)

print(response.content)