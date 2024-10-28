import requests
import certifi

# This URL is an example of a potentially insecure endpoint
url = "https://example.com"

# Using Certifi to get the default CA bundle
ca_bundle = certifi.where()

# Making a GET request to the URL
try:
    response = requests.get(url, verify=ca_bundle)
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.text)
except requests.exceptions.SSLError as e:
    print("SSL Error:", e)
except Exception as e:
    print("An error occurred:", e)