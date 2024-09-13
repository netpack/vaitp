import urllib.request # Python < 3.11
import base64

# Create a password manager
password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()

# Add a username and password
password_mgr.add_password(None, "http://example.com", "username", "password")

# Create a request
url = "http://example.com/"
request = urllib.request.Request(url)

# Add basic authentication headers manually
credentials = f"{password_mgr.find_user_password(None, url)[0]}:{password_mgr.find_user_password(None, url)[1]}"
credentials = credentials.encode('ascii')
credentials = base64.b64encode(credentials).decode('ascii')
request.add_header('Authorization', f'Basic {credentials}')

try:
    response = urllib.request.urlopen(request)
    print(response.read().decode())
except urllib.error.HTTPError as e:
    print(f"Error: {e.code} {e.reason}")