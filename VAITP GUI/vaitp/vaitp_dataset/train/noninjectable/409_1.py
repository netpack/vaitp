import httpx

def fetch_data(url):
    client = httpx.Client()
    response = client.get(url)  # Vulnerable to SSRF if 'url' is not properly validated
    return response.text

# Example usage
user_input = "http://localhost:8000/admin"  # Malicious input
data = fetch_data(user_input)
print(data)