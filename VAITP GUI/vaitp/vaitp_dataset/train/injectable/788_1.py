import requests

class PKIConnection:
    def __init__(self, base_url, verify=True):
        self.base_url = base_url
        self.verify = verify  # Allow setting verify parameter

    def get(self, endpoint):
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, verify=self.verify)  # Use the verify parameter
        return response

    def post(self, endpoint, data):
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, json=data, verify=self.verify)  # Use the verify parameter
        return response

# Example usage:
# connection = PKIConnection("https://example.com", verify=False)  # Can set verify to False if needed
# response = connection.get("some/endpoint")