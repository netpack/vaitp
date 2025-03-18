from flask import Flask, request, redirect
import requests

app = Flask(__name__)

@app.route('/fetch', methods=['GET'])
def fetch():
    url = request.args.get('url')
    
    # Redirecting to any user-supplied URL (SSRF risk)
    if 'redirect' in request.args:
        return redirect(url)

    response = requests.get(url)  # No validation
    return response.text

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
