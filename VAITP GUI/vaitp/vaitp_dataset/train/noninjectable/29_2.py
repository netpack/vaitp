# Import the urllib.parse module
from urllib.parse import urlparse

# Define a malicious URL that contains '\r' and '\n' characters in the path
# This URL will execute the os.system command and print the current user name
url = "http://example.com/\r\nimport os; os.system('whoami')\r\n"

# Parse the URL using the urlparse method
# This will not sanitize the input and allow the code injection
result = urlparse(url)

# Print the result
print(result)