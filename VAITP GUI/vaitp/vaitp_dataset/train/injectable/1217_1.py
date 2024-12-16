import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_command():
    user_input = request.json.get('command')
    
    # Validate user input to prevent command injection
    allowed_commands = ['ls', 'whoami', 'date']  # Example of allowed commands
    if user_input not in allowed_commands:
        return jsonify({'error': 'Invalid command'}), 400

    # Safely execute the command
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return jsonify({'output': result.stdout, 'error': result.stderr})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)