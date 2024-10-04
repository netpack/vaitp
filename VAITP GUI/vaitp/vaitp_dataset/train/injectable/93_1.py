# Import the requests module
import requests

# Define the URL to request
url = "https://example.com"

# Define the certificate file name
cert_file = "test.crt"

# Try to make an HTTPS request with the certificate file
try:
  response = requests.get(url, verify=cert_file)
  # Check if the response contains a valid certificate
  if "BEGIN CERTIFICATE" in response.text and "END CERTIFICATE" in response.text:
    print("The certificate is valid")
  else:
    print("The certificate is invalid")
except Exception as e:
  print("An error occurred:", e)