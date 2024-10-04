import requests
# The following line sets the Authorization header with the user's credentials
r = requests.get('https://example.com', auth=('user', 'pass'), trust_env=False)
# If example.com redirects to http://example.com, the credentials are not sent
print(r.status_code)