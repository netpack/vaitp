from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated user data
users = {
    1: {"name": "Alice", "sensitive_info": "alice_secret"},
    2: {"name": "Bob", "sensitive_info": "bob_secret"},
}

@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_info(user_id):
    user_info = users.get(user_id)
    if user_info:
        return jsonify(user_info)
    else:
        return jsonify({"error": "User  not found"}), 404

if __name__ == '__main__':
    app.run()