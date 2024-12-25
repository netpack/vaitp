import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

@app.route('/api/get_file', methods=['GET'])
def get_file():
    # Get the requested file name from the query parameters
    requested_file = request.args.get('file')
    
    if not requested_file:
        abort(400, description="File parameter is required")

    # Construct the file path
    base_dir = '/path/to/files'
    file_path = os.path.join(base_dir, requested_file)

    # Security check: Ensure the requested file is within the allowed directory
    real_file_path = os.path.realpath(file_path)
    real_base_dir = os.path.realpath(base_dir)

    if not real_file_path.startswith(real_base_dir):
       abort(403, description="Access to the file is forbidden")
    
    # Check if file exists
    if not os.path.exists(file_path):
        abort(404, description="File not found")

    # Serve the file
    try:
       return send_file(file_path)
    except Exception as e:
        abort(500, description=f"Error serving the file: {str(e)}")


if __name__ == '__main__':
    app.run()