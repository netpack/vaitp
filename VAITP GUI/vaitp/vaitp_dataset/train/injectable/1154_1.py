import os
from flask import Flask, send_from_directory, abort

app = Flask(__name__)

# Safe directory for serving files
SAFE_DIRECTORY = '/path/to/safe/directory'

@app.route('/files/<path:filename>')
def serve_file(filename):
    # Prevent directory traversal by validating the filename
    if '..' in filename or filename.startswith('/'):
        abort(403)  # Forbidden access

    return send_from_directory(SAFE_DIRECTORY, filename)

if __name__ == '__main__':
    app.run()