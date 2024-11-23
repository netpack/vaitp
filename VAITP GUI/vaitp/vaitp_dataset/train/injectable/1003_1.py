from flask import Flask, request, abort
import os

app = Flask(__name__)

# Define a safe directory for file writes
SAFE_DIRECTORY = '/safe/directory/'

@app.route('/update-resource-data/', methods=['POST'])
def update_resource_data():
    filename = request.form.get('filename')
    data = request.form.get('data')

    # Validate the filename to prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        abort(400, 'Invalid filename')

    # Construct the safe file path
    safe_path = os.path.join(SAFE_DIRECTORY, filename)

    # Write data to the file in the safe directory
    with open(safe_path, 'w') as f:
        f.write(data)

    return 'File updated successfully', 200

if __name__ == '__main__':
    app.run()