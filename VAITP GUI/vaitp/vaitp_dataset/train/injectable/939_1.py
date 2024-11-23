import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Environment variable to control access
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")

@app.route('/sensitive-data', methods=['GET'])
def get_sensitive_data():
    token = request.headers.get('Authorization')

    # Check if the provided token matches the expected token
    if token != f"Bearer {ACCESS_TOKEN}":
        return jsonify({"error": "Unauthorized access"}), 403

    # Return sensitive data only if authorized
    sensitive_data = {"secret": "This is sensitive information"}
    return jsonify(sensitive_data)

if __name__ == '__main__':
    app.run(debug=False)