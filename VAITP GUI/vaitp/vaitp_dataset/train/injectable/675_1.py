from flask import Flask, escape, request

app = Flask(__name__)

@app.route('/error')
def error():
    # Simulating an error message that could be returned
    error_message = request.args.get('message', '')
    
    # Properly escaping the error message to prevent XSS
    safe_error_message = escape(error_message)

    return f"<html><body><h1>Error</h1><p>{safe_error_message}</p></body></html>"

if __name__ == '__main__':
    app.run()