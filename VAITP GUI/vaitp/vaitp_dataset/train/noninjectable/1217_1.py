import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_command():
    user_input = request.json.get('command')
    
    # Vulnerable code: directly using user input in a system call
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)