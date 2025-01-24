from flask import Flask, request, abort, jsonify
from werkzeug.security import safe_str_cmp

app = Flask(__name__)

# Simulated user data
users = {
    1: {"name": "Alice", "sensitive_info": "alice_secret"},
    2: {"name": "Bob", "sensitive_info": "bob_secret"},
}

# Simulated current user ID (for demonstration purposes)
current_user_id = 1  # This would normally come from the user's session or authentication token

@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_info(user_id):
    # Check if the requested user ID matches the current user's ID
    if not safe_str_cmp(str(user_id), str(current_user_id)):
        abort(403)  # Forbidden access if the user is trying to access another user's info

    user_info = users.get(user_id)
    if user_info:
        user_info_copy = user_info.copy()
        del user_info_copy['sensitive_info']
        return jsonify(user_info_copy)
    else:
        abort(404)  # Not found if user does not exist

if __name__ == '__main__':
    app.run()
