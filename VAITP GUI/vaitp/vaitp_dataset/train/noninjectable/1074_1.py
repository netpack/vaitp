from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    # No size limit on uploads, leading to potential resource exhaustion
    file = request.files['file']
    file.save(f"./uploads/{file.filename}")
    return "File uploaded successfully", 200

if __name__ == '__main__':
    app.run()