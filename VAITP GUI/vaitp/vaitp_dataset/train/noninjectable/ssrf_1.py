from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    # Retrieve the URL from the query parameter without validation.
    url = request.args.get('url')
    if not url:
        return "Missing 'url' parameter.", 400
    try:
        # The server makes a GET request to the provided URL.
        response = requests.get(url)
        return response.text
    except Exception as e:
        return f"Error fetching URL: {e}", 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001)
