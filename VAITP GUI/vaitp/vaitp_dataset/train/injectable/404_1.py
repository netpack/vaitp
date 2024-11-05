from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('file')
    
    # Sanitize the input to prevent path traversal
    safe_filename = os.path.basename(filename)
    file_path = os.path.join('uploads', safe_filename)
    
    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()