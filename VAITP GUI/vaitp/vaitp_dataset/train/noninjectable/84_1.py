import urllib.request

def send_request(url):
    try:
        # Send a GET request to the provided URL
        response = urllib.request.urlopen(url)
        print(response.read().decode())
    except Exception as e:
        print(f"Error: {e}")

# Get user input for the URL
user_input = input("Enter a URL: ") # Like: "http://" + "example.com\r\nHeader: Injected"

# Construct the URL by concatenating the scheme and user input
url = "http://" + user_input

# Send the request
send_request(url) 