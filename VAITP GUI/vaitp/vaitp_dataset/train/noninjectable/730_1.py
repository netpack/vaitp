import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/api/get_file', methods=['GET'])
def get_file():
    # Get the requested file name from the query parameters
    requested_file = request.args.get('file')
    
    # Directly concatenate the requested file path
    file_path = os.path.join('/path/to/files', requested_file)

    # Serve the file without any validation
    return send_file(file_path)

if __name__ == '__main__':
    app.run()