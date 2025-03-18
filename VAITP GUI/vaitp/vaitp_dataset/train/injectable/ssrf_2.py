from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = {"netpack.pt"}

def is_safe_url(url):
    parsed_url = urlparse(url)
    
    # Validate scheme
    if parsed_url.scheme not in ["http", "https"]:
        return False

    # Block local network access
    if parsed_url.hostname in ["localhost", "127.0.0.1"] or parsed_url.hostname.startswith("192.168."):
        return False

    # Allow only whitelisted domains
    if parsed_url.hostname not in ALLOWED_DOMAINS:
        return False
    
    return True

@app.route('/fetch', methods=['GET'])
def fetch():
    url = request.args.get('url')

    if not is_safe_url(url):
        return jsonify({"error": "Invalid or blocked URL"}), 400

    try:
        response = requests.get(url, timeout=5, allow_redirects=False)  # Prevents open redirects
        return response.text, response.status_code
    except requests.RequestException:
        return jsonify({"error": "Failed to fetch URL"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
