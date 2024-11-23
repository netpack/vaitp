from flask import Flask, request, abort

app = Flask(__name__)

# A simple example of a command execution endpoint
@app.route('/execute', methods=['POST'])
def execute_command():
    user_input = request.form.get('command')

    # Fix: Validate and sanitize user input to prevent command injection
    allowed_commands = {'ls', 'pwd', 'whoami'}  # Example of allowed commands
    if user_input not in allowed_commands:
        abort(400, 'Invalid command')

    # Safe execution of the command
    import subprocess
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':
    app.run()