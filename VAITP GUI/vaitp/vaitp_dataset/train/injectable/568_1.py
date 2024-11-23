from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    # Secure the file path to prevent absolute path traversal
    safe_base_path = '/safe/directory/'
    safe_path = os.path.join(safe_base_path, filename)

    # Ensure the safe_path is within the safe_base_path
    if not os.path.abspath(safe_path).startswith(os.path.abspath(safe_base_path)):
        abort(403)  # Forbidden

    return send_file(safe_path)

if __name__ == '__main__':
    app.run()