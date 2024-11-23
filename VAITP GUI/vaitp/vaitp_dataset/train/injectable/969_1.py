from flask import Flask, send_file, abort, safe_join, send_from_directory
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    # Ensure that the filename is safe and does not allow absolute path traversal
    directory = os.path.join(app.root_path, 'files')
    safe_path = safe_join(directory, filename)

    if not safe_path.startswith(directory):
        abort(404)

    return send_file(safe_path)

if __name__ == '__main__':
    app.run()