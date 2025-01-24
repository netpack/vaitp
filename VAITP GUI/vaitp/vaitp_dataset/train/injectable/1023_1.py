from flask import Flask, request, jsonify
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

@app.route('/api/resource', methods=['POST'])
def update_resource():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON data provided"}), 400
    return jsonify({"status": "success", "data": data}), 200

if __name__ == '__main__':
    app.run()