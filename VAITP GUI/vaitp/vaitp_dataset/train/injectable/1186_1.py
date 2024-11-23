from flask import Flask, request, abort
import json

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    data = request.get_json()
    
    # Validate input to prevent arbitrary code execution
    if 'command' not in data or not isinstance(data['command'], str):
        abort(400, 'Invalid command')

    # Whitelist of allowed commands
    allowed_commands = ['safe_command_1', 'safe_command_2']
    
    if data['command'] not in allowed_commands:
        abort(403, 'Command not allowed')

    # Execute the command safely
    result = run_safe_command(data['command'])
    return json.dumps({'result': result})

def run_safe_command(command):
    # Implementation of safe command execution
    return f'Executed {command} safely'

if __name__ == '__main__':
    app.run()