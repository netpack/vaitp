from flask import Flask, request, abort
import os
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Middleware to check authentication for Supervisor API
@app.before_request
def require_authentication():
    if request.endpoint == 'supervisor_api':
        auth_token = request.headers.get('Authorization')
        if not auth_token or not is_valid_token(auth_token):
            abort(401)  # Unauthorized access

def is_valid_token(token):
    # Securely load token from an environment variable.
    hashed_token = os.environ.get('SUPERVISOR_TOKEN')
    if not hashed_token:
        return False
    
    return check_password_hash(hashed_token, token)

@app.route('/supervisor_api', methods=['GET', 'POST'])
def supervisor_api():
    # Your Supervisor API logic here
    return "Supervisor API Access Granted"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8123)
