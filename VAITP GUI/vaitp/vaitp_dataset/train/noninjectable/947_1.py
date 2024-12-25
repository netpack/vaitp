from flask import Flask, jsonify

app = Flask(__name__)

# It's highly discouraged to expose secret keys in this way in production.
# Using environment variables or secure storage mechanisms is recommended.
# For demonstration purposes only:
app.secret_key = 'your-secret-key' 

@app.route('/config', methods=['GET'])
def get_config():
    # Vulnerability: exposes sensitive configuration details
    # It's important to NOT expose sensitive information like secret keys.
    # This is for demonstration ONLY. In a real application, do not do this.
    return jsonify({'message': 'Configuration details are intentionally not exposed for security reasons.'})

if __name__ == '__main__':
    app.run()