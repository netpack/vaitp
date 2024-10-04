import requests

def safe_request(url, data):
    try:
        response = requests.post(url, data=data)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        # Handle the error or fail gracefully