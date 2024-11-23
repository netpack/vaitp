import requests

# Improperly validate SSL certificates (disabled verification)
response = requests.get('https://example.com', verify=False)

print(response.content)