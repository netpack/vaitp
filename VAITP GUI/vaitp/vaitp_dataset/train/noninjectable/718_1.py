from flask import Flask, request
import subprocess
import shlex

app = Flask(__name__)

@app.route('/edit/server', methods=['POST'])
def edit_server():
    # Get parameters from the request
    v_sftp_license = request.form.get('v_sftp_license')

    if not v_sftp_license:
        return "Error: v_sftp_license parameter is missing", 400

    # Sanitize user input before passing to subprocess
    try:
        args = ['some_command'] + shlex.split(v_sftp_license)
    except ValueError:
        return "Error: Invalid characters in v_sftp_license", 400
    
    # Execute the command with sanitized input
    result = subprocess.run(args, capture_output=True, text=True)


    if result.returncode != 0:
        return f"Error: Command failed with return code {result.returncode}\n{result.stderr}", 500

    return result.stdout, 200

if __name__ == '__main__':
    app.run()