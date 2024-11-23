from flask import Flask, jsonify

app = Flask(__name__)

# Exposing the secret key directly
app.secret_key = 'your-secret-key'

@app.route('/config', methods=['GET'])
def get_config():
    # Vulnerability: exposes sensitive configuration details
    return jsonify({'SECRET_KEY': app.secret_key})

if __name__ == '__main__':
    app.run()