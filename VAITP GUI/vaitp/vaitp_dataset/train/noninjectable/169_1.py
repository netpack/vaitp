from flask import Flask, request
import os

app = Flask(__name__)

# Vulnerable route that directly uses user input in a system command
@app.route('/vulnerable', methods=['GET'])
def vulnerable():
    user_input = request.args.get('input')
    # Insecure use of user input in a system command
    os.system(f"echo {user_input}")
    return "Command executed"

if __name__ == "__main__":
    app.run()