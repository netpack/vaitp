from flask import Flask, send_file

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    # Vulnerable to absolute path traversal
    return send_file(filename)

if __name__ == '__main__':
    app.run()