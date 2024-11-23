from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/edit/server', methods=['POST'])
def edit_server():
    # Get parameters from the request
    v_sftp_license = request.form.get('v_sftp_license')

    # Validate input to prevent command injection
    if not is_valid_license(v_sftp_license):
        return jsonify({'error': 'Invalid license format'}), 400

    # Safely execute a command using the validated input
    result = subprocess.run(['some_command', v_sftp_license], capture_output=True, text=True)

    return jsonify({'output': result.stdout}), 200

def is_valid_license(license_str):
    # Implement validation logic (e.g., regex pattern matching)
    return isinstance(license_str, str) and len(license_str) > 0 and len(license_str) < 100

if __name__ == '__main__':
    app.run()