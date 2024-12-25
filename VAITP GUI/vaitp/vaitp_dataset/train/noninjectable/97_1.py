# Import the urllib module
import urllib.request

try:
    # Open a local file with read permissions
    response = urllib.request.urlopen('file:///etc/passwd')

    # Print the file content
    print(response.read().decode('utf-8'))
except Exception as e:
    print(f"An error occurred: {e}")