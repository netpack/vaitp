import requests

proxies = {
    'http': 'http://username:password@proxy:8080',
    'https': 'http://username:password@proxy:8080'
}

response = requests.get('https://example.com', proxies=proxies)