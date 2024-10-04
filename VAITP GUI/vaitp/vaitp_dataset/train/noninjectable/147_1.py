# This code is vulnerable to CVE-2015-2296
# Do not run this code unless you trust the redirect URL
import requests # This will import the requests library
session = requests.Session() # This will create a session object
response = session.get("http://example.com") # This will send a GET request to example.com
# If example.com redirects to another URL with a cookie without a host value, the session object will store that cookie
# This can allow an attacker to hijack the session and gain access to sensitive information
print(response.text) # This will print the response content