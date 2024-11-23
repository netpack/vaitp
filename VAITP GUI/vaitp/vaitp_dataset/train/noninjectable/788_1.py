import requests

class PKIConnection:
    def __init__(self, base_url):
        self.base_url = base_url

    def get(self, endpoint):
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, verify=False)  # Hard-coded verify=False
        return response

    def post(self, endpoint, data):
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, json=data, verify=False)  # Hard-coded verify=False
        return response

# Example usage:
# connection = PKIConnection("https://example.com")
# response = connection.get("some/endpoint")