import os
from flask import Flask, request, abort

app = Flask(__name__)

# Define a safe upload folder
UPLOAD_FOLDER = '/path/to/safe/directory'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allow only specific file types
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if the post request has the file part
    if 'file' not in request.files:
        abort(400)  # Bad request
    file = request.files['file']

    # If user does not select file, browser also submit an empty part without filename
    if file.filename == '':
        abort(400)  # Bad request

    if file and allowed_file(file.filename):
        # Secure the filename and save the file
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully', 200
    else:
        abort(400)  # Bad request

if __name__ == '__main__':
    app.run()