import requests

def secure_request(url):
    try:
        # Use a more secure method to handle requests
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise an error for bad responses
        return response.json()  # Assuming the response is in JSON format
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

# Example usage
data = secure_request('https://api.example.com/data')
if data:
    print(data)