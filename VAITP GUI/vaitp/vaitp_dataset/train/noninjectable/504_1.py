from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    # Directly save the uploaded file without validation
    file = request.files['file']
    file.save('/path/to/storage/' + file.filename)  # Vulnerable to arbitrary file uploads
    return 'File uploaded successfully', 200

if __name__ == '__main__':
    app.run()