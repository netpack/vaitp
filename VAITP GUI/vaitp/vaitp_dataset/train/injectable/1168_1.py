from flask import Flask, request, abort, send_from_directory
import os

app = Flask(__name__)

# Define a safe directory to serve files from
SAFE_DIRECTORY = "/path/to/safe/directory"

@app.route('/files/<path:filename>', methods=['GET'])
def get_file(filename):
    # Validate the filename to prevent directory traversal attacks
    if '..' in filename or filename.startswith('/'):
        abort(403)  # Forbidden access

    # Serve the file only if it is within the safe directory
    return send_from_directory(SAFE_DIRECTORY, filename)

if __name__ == '__main__':
    app.run()