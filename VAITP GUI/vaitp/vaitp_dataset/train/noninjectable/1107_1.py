import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    # Vulnerable code: directly saving the uploaded file without validation
    file.save(os.path.join('/uploads', file.filename))
    return "File uploaded successfully", 200

if __name__ == '__main__':
    app.run()