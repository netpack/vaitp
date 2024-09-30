import urllib.parse
import urllib.request

def send_request(url):
    try:
        # Send a GET request to the provided URL
        response = urllib.request.urlopen(url)
        print(response.read().decode())
    except Exception as e:
        print(f"Error: {e}")

# Get user input for the URL
user_input = input("Enter a URL: ")

# Sanitize user input by encoding special characters
sanitized_input = urllib.parse.quote(user_input)

# Construct the URL by concatenating the scheme and sanitized user input
url = "http://" + sanitized_input

# Send the request
send_request(url)