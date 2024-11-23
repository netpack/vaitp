from flask import Flask, request

app = Flask(__name__)

@app.route('/fcopydir', methods=['POST'])
@app.route('/fmkdir', methods=['POST'])
@app.route('/frmdir', methods=['POST'])
@app.route('/getenv', methods=['GET'])
@app.route('/dumpenv', methods=['GET'])
@app.route('/fcopy', methods=['POST'])
@app.route('/fput', methods=['POST'])
@app.route('/fdel', methods=['POST'])
@app.route('/fmove', methods=['POST'])
@app.route('/fget', methods=['GET'])
@app.route('/fappend', methods=['POST'])
@app.route('/fdir', methods=['GET'])
@app.route('/getTraces', methods=['GET'])
@app.route('/kill', methods=['POST'])
@app.route('/pexec', methods=['POST'])
@app.route('/stop', methods=['POST'])
@app.route('/pythonexec', methods=['POST'])
def handle_request():
    # No authentication or validation
    # Directly execute the requested operation
    return "Request processed", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)