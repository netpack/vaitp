from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/files/<path:filename>')
def serve_file(filename):
    # Securely using send_file with validation
    base_dir = "."  # Or some other secure directory
    filepath = os.path.join(base_dir, filename)

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        abort(404)

    return send_file(filepath)

if __name__ == '__main__':
    app.run()