from flask import Flask, request
import subprocess

app = Flask(__name__)

# Patched route that avoids directly using user input in a system command
@app.route('/safe', methods=['GET'])
def safe():
    user_input = request.args.get('input')
    # Securely handling user input by avoiding direct system command execution
    subprocess.run(['echo', user_input], check=True)
    return "Command executed safely"

if __name__ == "__main__":
    app.run()