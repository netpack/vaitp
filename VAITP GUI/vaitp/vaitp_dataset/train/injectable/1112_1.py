import requests

# Properly validate SSL certificates
response = requests.get('https://example.com', verify=True)

print(response.content)