from flask import Flask, jsonify, request, escape

app = Flask(__name__)

@app.route('/api/contents', methods=['POST'])
def contents():
    # Simulated error message that could be sent as a response
    error_message = request.json.get('error_message', '')

    # Properly escape the error message to prevent XSS
    safe_error_message = escape(error_message)

    response = {
        'status': 'error',
        'message': safe_error_message
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run()