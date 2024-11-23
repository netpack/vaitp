from flask import Flask, send_file, abort, safe_join, send_from_directory
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    # Define a safe directory to serve files from
    safe_directory = '/path/to/safe/directory'
    
    # Use safe_join to prevent absolute path traversal
    safe_path = safe_join(safe_directory, filename)

    # Check if the file exists and is within the safe directory
    if os.path.isfile(safe_path):
        return send_file(safe_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()