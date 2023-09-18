import requests

# Define a target URL (replace with your desired URL)
target_url = "https://example.com"

# Perform an HTTPS GET request using the requests library
try:
    response = requests.get(target_url)
    
    # Check the response status code
    if response.status_code == 200:
        print("Status:", response.status_code)
        print("Response Data:")
        print(response.text)
    else:
        print("HTTP request failed with status code:", response.status_code)

except requests.exceptions.RequestException as e:
    print("An error occurred:", str(e))
