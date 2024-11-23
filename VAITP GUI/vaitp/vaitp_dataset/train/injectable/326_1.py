# Fixed version of the vulnerable code
import requests

def safe_fetch_user_agents():
    # Use a trusted source for user agents
    trusted_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        # Add more trusted user agents as needed
    ]
    return trusted_user_agents

def fetch_data(url):
    user_agents = safe_fetch_user_agents()
    headers = {'User -Agent': user_agents[0]}  # Use a safe user agent
    response = requests.get(url, headers=headers)
    return response.content

# Example usage
url = "https://example.com/api/data"
data = fetch_data(url)
print(data)