# Import the urllib module
import urllib

# Open a local file with read permissions
response = urllib.urlopen('local_file:///etc/passwd')

# Print the file content
print(response.read())