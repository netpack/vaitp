import urllib3

# Create an urllib3 pool manager
http = urllib3.PoolManager()

# Make a GET request to a website
response = http.request("GET", "https://example.com")

# Print the status code and the data
print(response.status)
print(response.data)