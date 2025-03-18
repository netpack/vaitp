from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch', methods=['GET'])
def fetch():
    url = request.args.get('url')
    response = requests.get(url)  # No validation, SSRF possible
    return response.text

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
