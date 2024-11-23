from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def handle_file_upload():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    # No validation or sanitization of the file extension or content type
    file.save('/path/to/save/' + file.filename)
    return 'File uploaded successfully', 200

if __name__ == '__main__':
    app.run()