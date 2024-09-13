import urllib.request # Python < 3.11

# Create a password manager
password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()

# Add a username and password
password_mgr.add_password(None, "http://example.com", "username", "password")

# Create an authentication handler
auth_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)

# Create an opener with the authentication handler
opener = urllib.request.build_opener(auth_handler)

# Install the opener
urllib.request.install_opener(opener)

# Make a request to a malicious server
url = "http://malicious-server.com/"
request = urllib.request.Request(url)

try:
    response = urllib.request.urlopen(request)
    print(response.read().decode())
except urllib.error.HTTPError as e:
    print(f"Error: {e.code} {e.reason}")