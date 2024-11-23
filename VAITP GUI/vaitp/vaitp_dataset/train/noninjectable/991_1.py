from flask import Flask, request

app = Flask(__name__)

@app.route('/api/some_endpoint', methods=['GET'])
def some_endpoint():
    # No CSRF protection implemented
    # Any GET request can trigger this endpoint
    return "API call successful", 200

if __name__ == '__main__':
    app.run()