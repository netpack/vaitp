from flask import Flask, send_file, abort
import os

app = Flask(__name__)

# Define a safe base directory
BASE_DIR = '/safe/base/directory'

@app.route('/resource-data/<path:filename>.txt', methods=['GET'])
def get_resource_data(filename):
    # Sanitize the filename to prevent directory traversal
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(BASE_DIR, safe_filename + '.txt')

    # Check if the file exists within the base directory
    if os.path.isfile(file_path):
        return send_file(file_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()