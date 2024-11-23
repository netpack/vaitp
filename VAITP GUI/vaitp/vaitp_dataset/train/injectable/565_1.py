from flask import Flask, request, escape

app = Flask(__name__)

@app.route('/trigger', methods=['GET'])
def trigger():
    origin = request.args.get('origin', '')
    # Properly escape the origin parameter to prevent XSS
    safe_origin = escape(origin)
    return f'Triggered from {safe_origin}'

if __name__ == '__main__':
    app.run()