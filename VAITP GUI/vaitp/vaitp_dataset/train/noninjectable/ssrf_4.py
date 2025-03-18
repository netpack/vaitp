from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch', methods=['GET'])
def fetch():
    url = request.args.get('url')
    follow_redirects = request.args.get('redirect', 'true').lower() == 'true'
    custom_headers = {"User-Agent": request.args.get('user_agent', 'Mozilla/5.0')}

    response = requests.get(url, headers=custom_headers, allow_redirects=follow_redirects)  # SSRF risk
    return response.text

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
