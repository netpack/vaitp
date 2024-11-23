from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/api/some_endpoint', methods=['GET'])
def some_endpoint():
    # Check for CSRF token in the request headers
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or csrf_token != 'expected_csrf_token':
        return "CSRF token is missing or invalid", 403

    # Proceed with the API call
    return "API call successful", 200

if __name__ == '__main__':
    app.run()