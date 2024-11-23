import certifi
import requests

# Using an older version of Certifi that includes GLOBALTRUST root certificates
# Simulating a request that may be vulnerable
response = requests.get('https://example.com', verify=certifi.where())
print(response.status_code)