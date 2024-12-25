from flask import Flask, send_file, abort
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads' # Or whatever directory you want to serve files from
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/download/<path:filename>')
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.isfile(file_path):
        abort(404)

    return send_file(file_path)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) #Ensure the folder exists
    app.run(debug=True)