from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('file')
    # Vulnerable to path traversal
    file_path = os.path.join('uploads', filename)
    
    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()