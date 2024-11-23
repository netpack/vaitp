import requests
from democritus_user_agents import get_random_user_agent  # Vulnerable import

def fetch_data(url):
    user_agent = get_random_user_agent()  # Potentially unsafe user agent
    headers = {'User -Agent': user_agent}
    response = requests.get(url, headers=headers)
    return response.content

# Example usage
url = "https://example.com/api/data"
data = fetch_data(url)
print(data)