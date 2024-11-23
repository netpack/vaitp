import requests
from requests.auth import HTTPBasicAuth

# Configuration for OAuth2.0 Client Credential Flow
client_id = 'your_client_id'
client_secret = 'your_client_secret'
issuer_url = 'https://your-issuer-url.com/oauth/token'

# Use verify=True to ensure TLS certificates are verified
response = requests.post(
    issuer_url,
    auth=HTTPBasicAuth(client_id, client_secret),
    verify=True,  # This ensures that the TLS certificate is verified
    data={'grant_type': 'client_credentials'}
)

if response.status_code == 200:
    print("Access token retrieved successfully.")
    access_token = response.json().get('access_token')
    print("Access Token:", access_token)
else:
    print("Failed to retrieve access token:", response.status_code, response.text)