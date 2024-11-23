from flask import Flask, request

app = Flask(__name__)

@app.route('/error')
def error():
    # Simulating an error message that could be returned
    error_message = request.args.get('message', '')

    # Not escaping the error message, which can lead to XSS
    return f"<html><body><h1>Error</h1><p>{error_message}</p></body></html>"

if __name__ == '__main__':
    app.run()