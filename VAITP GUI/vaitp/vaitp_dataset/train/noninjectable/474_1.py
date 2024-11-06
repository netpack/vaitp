import requests
from requests_kerberos import HTTPKerberosAuth

# Create a Kerberos authentication object
kerberos_auth = HTTPKerberosAuth(mutual_authentication=HTTPKerberosAuth.OPTIONAL)

# Make a request to a service
response = requests.get('http://example.com/protected', auth=kerberos_auth)

# Check if the request was successful
if response.status_code == 200:
    print("Access granted")
else:
    print("Access denied")