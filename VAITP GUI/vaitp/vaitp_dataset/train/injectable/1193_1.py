
from flask import Flask, request, jsonify, abort
import secrets

app = Flask(__name__)

# Simulated database of users
users = {
    1: {"name": "Alice", "email": "alice@example.com", "token": secrets.token_hex(32)},
    2: {"name": "Bob", "email": "bob@example.com", "token": secrets.token_hex(32)},
}


# Middleware to check authorization
def is_authorized(user_id, token):
    user = users.get(user_id)
    if user and secrets.compare_digest(user.get("token"), token):
        return True
    return False


@app.route('/api/myapp/index/user/info', methods=['GET'])
def get_user_info():
    user_id = request.args.get('id', type=int)
    token = request.headers.get('Authorization')

    if user_id is None or token is None or not is_authorized(user_id, token):
        abort(403)  # Forbidden if not authorized

    user_info = users.get(user_id)
    if user_info is None:
        abort(404)  # Not found if user does not exist

    return jsonify({"name": user_info['name'], "email": user_info['email']})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')