from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    # No limit on the number of file parts
    for file in request.files.getlist('files'):
        # Save or process the file
        pass

    return 'Files uploaded successfully', 200

if __name__ == '__main__':
    app.run()