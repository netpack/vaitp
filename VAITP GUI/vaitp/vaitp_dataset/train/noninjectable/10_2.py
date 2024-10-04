# Import the urllib.parse module
import urllib.parse

# Define a function that checks if a URL starts with https://
def check_url_scheme(url):
    # Parse the URL using the urllib.parse.urlparse function
    parsed_url = urllib.parse.urlparse(url)
    # Check if the URL scheme is https
    if parsed_url.scheme == "https":
        return True
    else:
        return False

# Get the user input
user_input = input("Enter a URL: ")

# Check if the user input is a valid and secure URL
if check_url_scheme(user_input):
    print("The URL is valid and secure.")
else:
    print("The URL is invalid or insecure.")