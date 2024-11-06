from flask import Flask, request
import os

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        file.save(os.path.join('uploads', file.filename))  # Secure file upload
        return 'File uploaded successfully', 200
    else:
        return 'File type not allowed', 400