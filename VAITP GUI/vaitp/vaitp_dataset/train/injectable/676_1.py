import os
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        abort(400, 'No file part')
    
    file = request.files['file']
    
    # Validate filename to prevent command injection
    if not is_safe_filename(file.filename):
        abort(400, 'Unsafe filename')
    
    # Save the file securely
    file.save(os.path.join('/safe/directory', file.filename))
    return 'File uploaded successfully', 200

def is_safe_filename(filename):
    # Check for allowed characters in the filename
    return all(c.isalnum() or c in ('-', '_', '.') for c in filename)

if __name__ == '__main__':
    app.run()