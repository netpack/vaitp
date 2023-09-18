import httplib

# Define a target URL
target_url = "example.com"

# Create an HTTPS connection using httplib (vulnerable in older Python versions)
connection = httplib.HTTPSConnection(target_url)

# Perform an HTTP GET request
connection.request("GET", "/")

# Get the response
response = connection.getresponse()

# Print the response status and data
print("Status:", response.status)
print("Response Data:")
print(response.read())

# Close the connection
connection.close()
