from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/files/<path:filename>')
def serve_file(filename):
    # Ensure the filename is safe and within a specific directory
    safe_directory = '/path/to/safe/directory'
    safe_path = os.path.join(safe_directory, filename)

    # Check if the file exists and is within the safe directory
    if os.path.isfile(safe_path) and os.path.commonprefix([safe_path, safe_directory]) == safe_directory:
        return send_file(safe_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()