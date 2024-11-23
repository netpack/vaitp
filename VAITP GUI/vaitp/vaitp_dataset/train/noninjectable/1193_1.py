from flask import Flask, request, jsonify

app = Flask(__name__)

# Sample user data
users = {
    1: {"name": "Alice", "email": "alice@example.com"},
    2: {"name": "Bob", "email": "bob@example.com"},
}

@app.route('/api/myapp/index/user/info', methods=['GET'])
def get_user_info():
    user_id = request.args.get('id')
    # Vulnerability: No authorization check
    user_info = users.get(int(user_id))
    if user_info:
        return jsonify(user_info)
    else:
        return jsonify({"error": "User  not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)