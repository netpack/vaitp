from flask import Flask, request, jsonify
import requests
import validators
from urllib.parse import urlparse

app = Flask(__name__)

# Allowlist of domains that are safe to fetch
ALLOWED_DOMAINS = {"netpack.pt"}

# Function to check if the URL is safe
def is_url_safe(url):
    try:
        parsed_url = urlparse(url)
        
        # Validate URL format
        if not validators.url(url):
            return False
        
        # Ensure only HTTP and HTTPS are allowed
        if parsed_url.scheme not in ["http", "https"]:
            return False

        # Prevent local network SSRF (internal/private IPs)
        if parsed_url.hostname in ["localhost", "127.0.0.1"] or parsed_url.hostname.startswith("192.168."):
            return False
        
        # Restrict access to allowed domains only
        if parsed_url.hostname not in ALLOWED_DOMAINS:
            return False
        
        return True
    except Exception:
        return False

@app.route('/fetch', methods=['GET'])
def fetch():
    url = request.args.get('url')

    if not url or not is_url_safe(url):
        return jsonify({"error": "Invalid or blocked URL"}), 400

    try:
        response = requests.get(url, timeout=5)  # Timeout prevents slow attacks
        return response.text, response.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"Error fetching URL: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
