import os
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/git_content', methods=['GET'])
def git_content():
    user_role = request.args.get('role')
    if user_role != 'Viewer':
        abort(403)  # Forbidden for non-viewers

    # Get the requested file path from the query parameter
    requested_file = request.args.get('file')

    # Validate the requested file path to prevent path traversal
    safe_base_path = '/safe/base/directory/'
    safe_path = os.path.normpath(os.path.join(safe_base_path, requested_file))

    # Ensure the safe path starts with the safe base path
    if not safe_path.startswith(safe_base_path):
        abort(400)  # Bad request for invalid file access

    # Read the content of the file
    try:
        with open(safe_path, 'r') as file:
            content = file.read()
        return content, 200
    except FileNotFoundError:
        abort(404)  # Not found if the file does not exist

if __name__ == '__main__':
    app.run()