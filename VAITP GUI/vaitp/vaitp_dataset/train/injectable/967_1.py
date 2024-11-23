from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Securely handle incoming requests and avoid executing arbitrary code
@app.route('/api/data', methods=['POST'])
def handle_data():
    # Validate and sanitize input data
    user_data = request.json.get('data', '')
    
    # Example of input validation
    if not isinstance(user_data, str) or len(user_data) > 100:
        return jsonify({"error": "Invalid input"}), 400
    
    # Process the sanitized data (e.g., store it securely)
    # Avoid executing any code from user input
    # For demonstration, we just return the sanitized data
    return jsonify({"received": user_data}), 200

if __name__ == '__main__':
    app.run(debug=False)