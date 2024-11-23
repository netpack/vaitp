from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    # Limit the size of the upload to prevent resource exhaustion
    if request.content_length > 16 * 1024 * 1024:  # Limit to 16 MB
        return "File too large", 413
    # Handle file upload
    file = request.files['file']
    file.save(f"./uploads/{file.filename}")
    return "File uploaded successfully", 200

if __name__ == '__main__':
    app.run()