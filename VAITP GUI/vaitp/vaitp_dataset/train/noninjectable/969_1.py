from flask import Flask, send_file, abort
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/download/<filename>')
def download_file(filename):
    # Safe use of send_file with path joining and security check
    safe_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(safe_path):
        abort(404, description="File not found")
    return send_file(safe_path, as_attachment=True)


if __name__ == '__main__':
    # Create upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
      os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)