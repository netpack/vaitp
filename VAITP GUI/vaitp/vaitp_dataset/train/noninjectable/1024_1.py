import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/notebooks', methods=['POST'])
def create_notebook():
    # Simulating a notebook creation process
    data = request.json
    if not data or 'name' not in data:
        # Vulnerable to XSS: error message not escaped
        error_message = "Invalid notebook data."
        return jsonify({'error': error_message}), 400

    notebook_name = data['name']
    # Further processing to create the notebook...
    
    return jsonify({'message': f'Notebook {notebook_name} created successfully!'}), 201

if __name__ == '__main__':
    app.run(debug=True)