import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_command():
    if not request.json or 'command' not in request.json:
        return jsonify({'error': 'No command provided'}), 400

    command = request.json['command']
    # Vulnerable: executes any command passed in the request
    output = os.popen(command).read()
    return jsonify({'output': output}), 200

if __name__ == '__main__':
    app.run()