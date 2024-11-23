from flask import Flask, request, abort

app = Flask(__name__)

# Middleware to check authentication for Supervisor API
@app.before_request
def require_authentication():
    if request.endpoint in ['supervisor_api']:
        auth_token = request.headers.get('Authorization')
        if not auth_token or not is_valid_token(auth_token):
            abort(401)  # Unauthorized access

def is_valid_token(token):
    # Implement token validation logic here
    # For example, check against a list of valid tokens or a database
    valid_tokens = ['your_valid_token_here']
    return token in valid_tokens

@app.route('/supervisor_api', methods=['GET', 'POST'])
def supervisor_api():
    # Your Supervisor API logic here
    return "Supervisor API Access Granted"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8123)