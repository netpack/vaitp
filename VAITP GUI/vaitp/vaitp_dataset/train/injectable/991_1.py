from flask import Flask, request, make_response, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/api/some_endpoint', methods=['GET'])
def some_endpoint():
    if 'csrf_token' not in session:
        return "CSRF token is missing", 403
    
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or csrf_token != session['csrf_token']:
        return "CSRF token is invalid", 403

    return "API call successful", 200

@app.route('/get_csrf', methods=['GET'])
def get_csrf():
    session['csrf_token'] = os.urandom(16).hex()
    return {"csrf_token": session['csrf_token']}, 200


if __name__ == '__main__':
    app.run()
