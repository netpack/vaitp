import requests

class Resource:
    @staticmethod
    def get(url):
        # Vulnerable to SSRF
        response = requests.get(url)
        return response.json()

# Example usage
url = "http://internal-service.local/resource"  # Potential SSRF target
data = Resource.get(url)
print(data)