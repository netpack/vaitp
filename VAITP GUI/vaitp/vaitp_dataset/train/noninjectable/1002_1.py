from flask import Flask, send_file

app = Flask(__name__)

@app.route('/resource-data/<path:filename>.txt', methods=['GET'])
def get_resource_data(filename):
    # Vulnerable code that allows directory traversal
    file_path = f'./{filename}.txt'
    return send_file(file_path)

if __name__ == '__main__':
    app.run()