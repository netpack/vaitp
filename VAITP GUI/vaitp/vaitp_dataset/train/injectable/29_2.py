# Import the requests library
import requests

# Define a malicious URL that contains '\r' and '\n' characters in the path
# This URL will execute the os.system command and print the current user name
url = "http://example.com/\r\nimport os; os.system(\"whoami\")\r\n"

# Parse the URL using the requests library
# This will not execute the malicious code and return a response object
response = requests.get(url)

# Print the status code of the response
print(response.status_code)