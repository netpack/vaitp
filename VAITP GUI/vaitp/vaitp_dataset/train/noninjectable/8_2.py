import requests

# Define the proxy URL and credentials
proxy_url = "http://user:pass@proxy.example.com:8080"
proxy_dict = {"http": proxy_url, "https": proxy_url}

# Define the target URL
target_url = "http://example.com"

# Send a HTTP request using the requests.get function with the proxy_dict parameter
response = requests.get(target_url, proxies=proxy_dict)

# Print the response status code and content
print(response.status_code)
print(response.text)