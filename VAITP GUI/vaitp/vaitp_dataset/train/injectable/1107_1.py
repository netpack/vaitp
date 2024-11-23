import os
from flask import Flask, request, abort

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        abort(400, "No file part")
    file = request.files['file']
    if file.filename == '':
        abort(400, "No selected file")
    if file and allowed_file(file.filename):
        safe_path = os.path.join('/safe/upload/directory', file.filename)
        file.save(safe_path)
        return "File uploaded successfully", 200
    else:
        abort(400, "File type not allowed")

if __name__ == '__main__':
    app.run()