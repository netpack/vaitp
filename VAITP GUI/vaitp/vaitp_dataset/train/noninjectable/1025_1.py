from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/api/contents', methods=['POST'])
def contents():
    # Simulated error message that could be sent as a response
    error_message = request.json.get('error_message', '')

    # Vulnerable to XSS as the error message is not escaped
    response = {
        'status': 'error',
        'message': error_message  # Directly including user input
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run()