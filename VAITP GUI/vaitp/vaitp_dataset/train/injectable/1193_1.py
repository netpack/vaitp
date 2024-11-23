from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# Simulated database of users
users = {
    1: {"name": "Alice", "email": "alice@example.com"},
    2: {"name": "Bob", "email": "bob@example.com"},
}

# Middleware to check authorization
def is_authorized(user_id):
    # Implement your authorization logic here
    # For demonstration, let's assume only user with ID 1 is authorized
    return user_id == 1

@app.route('/api/myapp/index/user/info', methods=['GET'])
def get_user_info():
    user_id = request.args.get('id', type=int)

    if user_id is None or not is_authorized(user_id):
        abort(403)  # Forbidden if not authorized

    user_info = users.get(user_id)
    if user_info is None:
        abort(404)  # Not found if user does not exist

    return jsonify(user_info)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)