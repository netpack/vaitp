from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    data = request.get_json()
    
    # Directly executing user-provided command without validation
    command = data.get('command')
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return {'output': result.stdout, 'error': result.stderr}

if __name__ == '__main__':
    app.run()