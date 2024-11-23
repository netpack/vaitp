import requests

def download_frp_client(url):
    response = requests.get(url)
    binary_path = 'frp_client'
    
    with open(binary_path, 'wb') as file:
        file.write(response.content)

    print("FRP client downloaded without integrity check.")

# Example usage
url = 'https://example.com/path/to/frp_client'
download_frp_client(url)