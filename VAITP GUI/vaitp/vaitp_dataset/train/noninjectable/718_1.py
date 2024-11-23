from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/edit/server', methods=['POST'])
def edit_server():
    # Get parameters from the request
    v_sftp_license = request.form.get('v_sftp_license')

    # Directly execute a command with user input
    result = subprocess.run(['some_command', v_sftp_license], capture_output=True, text=True)

    return result.stdout, 200

if __name__ == '__main__':
    app.run()