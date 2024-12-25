from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    # Secure use of send_file with sanitization to prevent path traversal
    base_dir = os.path.abspath(".")  # Or some other safe base directory
    safe_path = os.path.join(base_dir, filename)
    
    if not safe_path.startswith(base_dir):
        abort(400, description="Invalid file path")

    if not os.path.isfile(safe_path):
       abort(404, description="File not found")
    
    return send_file(safe_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)