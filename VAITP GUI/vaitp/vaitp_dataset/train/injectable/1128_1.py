
from flask import Flask, request, jsonify, abort
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Simulated user database
users = {
    "user1": {"password": "pbkdf2:sha256:100000$5s6ecwlK$d89c6c2338eb27b18db061c55e14d226949c3c761de9f7476d257651360927b6", "active": False},
}

@app.route('/api/v1/users/<username>/activate', methods=['POST'])
def activate_user(username):
    if username not in users:
        abort(404)  # User not found

    data = request.json
    new_password = data.get('new_password')

    # Check if the user is authorized to activate
    if not is_user_authorized(username):
        abort(403)  # Forbidden

    # Check if the new password is valid
    if not new_password or len(new_password) < 8:
        abort(400)  # Bad Request

    # Activate user only if the password is correct
    if check_password_hash(users[username]['password'], new_password):
        users[username]['active'] = True
        return jsonify({"message": "User activated successfully."}), 200
    else:
        abort(401)  # Unauthorized

def is_user_authorized(username):
    # Implement proper authorization checks here
    return True  # Simplified for demonstration

if __name__ == '__main__':
    app.run(debug=True)