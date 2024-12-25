import os
from flask import Flask, request, abort, send_file

app = Flask(__name__)

# Define a safe directory to serve files from
SAFE_DIRECTORY = "/path/to/safe/directory"

@app.route('/api/get_file', methods=['GET'])
def get_file():
    # Get the requested file name from the query parameters
    requested_file = request.args.get('file')
    
    if not requested_file:
        abort(400) # Bad Request if no file parameter is given

    # Normalize the path to prevent directory traversal
    safe_path = os.path.normpath(os.path.join(SAFE_DIRECTORY, requested_file))

    # Ensure the safe path starts with the safe directory
    if not safe_path.startswith(SAFE_DIRECTORY):
        abort(403)  # Forbidden access

    # Check if the file exists and is a file
    if os.path.isfile(safe_path):
        return send_file(safe_path)  # Serve the file securely
    else:
        abort(404)  # File not found

if __name__ == '__main__':
    app.run(debug=True)