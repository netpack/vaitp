from flask import Flask, request, abort
import os

app = Flask(__name__)

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'jpg', 'jpeg', 'png', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        abort(400, 'No file part')
    
    file = request.files['file']
    
    if file.filename == '':
        abort(400, 'No selected file')
    
    if file and allowed_file(file.filename):
        # Securely save the file
        filename = secure_filename(file.filename)
        file.save(os.path.join('/path/to/upload', filename))
        return 'File successfully uploaded', 200
    else:
        abort(400, 'File type not allowed')

if __name__ == '__main__':
    app.run()