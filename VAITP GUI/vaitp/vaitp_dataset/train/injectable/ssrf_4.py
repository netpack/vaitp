from flask import Flask, request, jsonify
import requests
import validators
from urllib.parse import urlparse
import logging

app = Flask(__name__)

ALLOWED_DOMAINS = {"netpack.pt"}
BLOCKED_IPS = {"127.0.0.1", "192.168.1.1"}

logging.basicConfig(level=logging.INFO)

def is_safe_url(url):
    try:
        parsed_url = urlparse(url)
        
        if not validators.url(url):
            return False

        if parsed_url.scheme not in ["http", "https"]:
            return False

        if parsed_url.hostname in ["localhost"] or parsed_url.hostname in BLOCKED_IPS:
            return False

        if parsed_url.hostname not in ALLOWED_DOMAINS:
            return False
        
        return True
    except Exception:
        return False

@app.route('/fetch', methods=['GET'])
def fetch():
    url = request.args.get('url')
    user_agent = request.args.get('user_agent', 'Mozilla/5.0')

    if not is_safe_url(url):
        logging.warning(f"Blocked request to {url}")
        return jsonify({"error": "Invalid or blocked URL"}), 400

    headers = {"User-Agent": user_agent}

    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        logging.info(f"Successful request to {url}")
        return response.text, response.status_code
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return jsonify({"error": "Failed to fetch URL"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
