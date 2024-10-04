import requests
# The following line sets the Authorization header with the user's credentials
r = requests.get('https://example.com', auth=('user', 'pass'))
# If example.com redirects to http://example.com, the credentials are sent in cleartext
print(r.status_code)