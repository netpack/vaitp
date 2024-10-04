# Import the urllib3 module
import urllib3

# Define a URL to request
url = "https://example.com"

# Define a certificate file name
cert_file = "test.crt"

# Create an SSLContext object with the certificate file
ssl_context = ssl.create_default_context()
ssl_context.load_cert_chain(cert_file)

# Create an HTTPSConnection object with the SSLContext object
https_connection = urllib3.PoolManager(ssl_context)

# Try to make an HTTPS request with the HTTPSConnection object
try:
  response = https_connection.request("GET", url)
  # Check if the response contains a valid certificate
  if "BEGIN CERTIFICATE" in response.data and "END CERTIFICATE" in response.data:
    print("The certificate is valid")
  else:
    print("The certificate is invalid")
except Exception as e:
  print("An error occurred:", e)