from flask import Flask, send_from_directory

app = Flask(__name__)

@app.route('/files/<path:filename>', methods=['GET'])
def get_file(filename):
    # Insufficient input validation allowing potential directory traversal
    return send_from_directory('.', filename)  # Serving files from the current directory

if __name__ == '__main__':
    app.run()