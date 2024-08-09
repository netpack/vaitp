import requests

proxies = {
    'http': 'http://username:password@proxy:8080',
    'https': 'http://username:password@proxy:8080'
}

response = requests.get('https://example.com', proxies=proxies, allow_redirects=False)
if response.status_code == 302:
    response = requests.get(response.headers['Location'], proxies=proxies)