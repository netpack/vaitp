from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400
    
    # Directly save the uploaded file without checking its type
    file.save(f'/path/to/upload/{file.filename}')
    return 'File successfully uploaded', 200

if __name__ == '__main__':
    app.run()