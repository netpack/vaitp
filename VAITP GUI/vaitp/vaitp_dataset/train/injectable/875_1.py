import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# Function to safely execute commands
def safe_execute(command):
    # Whitelist of allowed commands
    allowed_commands = {'ls', 'pwd', 'whoami'}
    command_parts = command.split()
    if command_parts and command_parts[0] in allowed_commands:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            return result
        except subprocess.CalledProcessError as e:
            return e
    else:
        return "Command not allowed", 403

@app.route('/execute', methods=['POST'])
def execute_command():
    if not request.json or 'command' not in request.json:
        return jsonify({'error': 'No command provided'}), 400

    command = request.json['command']
    output = safe_execute(command)
    if isinstance(output, tuple):
        return jsonify({'error': output[0]}), output[1]
    elif isinstance(output, subprocess.CalledProcessError):
        return jsonify({'output': output.stdout, 'error': output.stderr, 'returncode':output.returncode}), 200
    else:
        return jsonify({'output': output.stdout, 'error': output.stderr}), 200

if __name__ == '__main__':
    app.run(debug=True)