# Example of the vulnerable code allowing direct access to example files

from flask import Flask

app = Flask(__name__)

@app.route('/spyce/examples/<filename>')
def serve_example(filename):
    # Directly serve example files without restrictions
    file_path = f'spyce/examples/{filename}'
    return open(file_path).read()  # Vulnerable to exposing sensitive information

if __name__ == '__main__':
    app.run()