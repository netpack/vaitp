import requests

def vulnerable_request(url):
    # This code is vulnerable to code execution via untrusted input
    response = requests.get(url)
    exec(response.text)  # Executing arbitrary code from the response
    return response.json()  # Assuming the response is in JSON format

# Example usage
data = vulnerable_request('https://api.example.com/data')
if data:
    print(data)