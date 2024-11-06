from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    file.save(f'uploads/{file.filename}')  # Vulnerable to arbitrary file upload
    return 'File uploaded successfully', 200