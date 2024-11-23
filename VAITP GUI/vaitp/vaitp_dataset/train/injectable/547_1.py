from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/download/<filename>')
def download_file(filename):
    # Sanitize the filename to prevent absolute path traversal
    safe_filename = os.path.basename(filename)
    file_path = os.path.join('safe_directory', safe_filename)

    if os.path.isfile(file_path):
        return send_file(file_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()