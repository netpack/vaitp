import requests

# Define a URL (replace with your desired URL)
url = "https://example.com"

try:
    # Perform an HTTPS GET request using the requests library
    response = requests.get(url, verify=True)
    
    # Check the response status code
    if response.status_code == 200:
        print("Status:", response.status_code)
        print("Response Data:")
        print(response.text)
    else:
        print("HTTP request failed with status code:", response.status_code)

except requests.exceptions.RequestException as e:
    print("An error occurred:", str(e))

