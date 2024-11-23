from flask import Flask, request, abort

app = Flask(__name__)

# Set a limit on the number of file parts to prevent DoS attacks
MAX_FILE_PARTS = 10

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check the number of file parts in the request
    if len(request.files) > MAX_FILE_PARTS:
        abort(413)  # Payload Too Large

    # Process the files
    for file in request.files.getlist('files'):
        # Save or process the file
        pass

    return 'Files uploaded successfully', 200

if __name__ == '__main__':
    app.run()