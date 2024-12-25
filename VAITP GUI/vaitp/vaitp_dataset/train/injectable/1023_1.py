from flask import Flask, request, jsonify
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

@app.route('/api/resource', methods=['POST'])
# @csrf.exempt  # This line should be removed to enforce CSRF protection
def update_resource():
    # Logic to update the resource
    data = request.json
    # Process the data
    return jsonify({"status": "success", "data": data}), 200

if __name__ == '__main__':
    app.run()