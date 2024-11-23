from flask import Flask, jsonify

app = Flask(__name__)

# Set a secure secret key
app.secret_key = 'your-secure-secret-key'

@app.route('/config', methods=['GET'])
def get_config():
    # Restrict access to the configuration details
    return jsonify({'message': 'Access denied'}), 403

if __name__ == '__main__':
    app.run()