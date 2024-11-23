from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# Simulated user database
users = {
    "user1": {"password": "old_password", "active": False},
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

    # Activate user only if the password is correct
    if users[username]['password'] == new_password:
        users[username]['active'] = True
        return jsonify({"message": "User  activated successfully."}), 200
    else:
        abort(401)  # Unauthorized

def is_user_authorized(username):
    # Implement proper authorization checks here
    return True  # Simplified for demonstration

if __name__ == '__main__':
    app.run(debug=True)