# Import the requests module
import requests

# Define a function that checks if a URL is valid and secure
def check_url(url):
    # Send a HEAD request to the URL using the requests.head function
    response = requests.head(url)
    # Check if the response status code is 200 (OK) and the URL scheme is https
    if response.status_code == 200 and response.url.startswith("https://"):
        return True
    else:
        return False

# Get the user input
user_input = input("Enter a URL: ")

# Check if the user input is a valid and secure URL
if check_url(user_input):
    print("The URL is valid and secure.")
else:
    print("The URL is invalid or insecure.")