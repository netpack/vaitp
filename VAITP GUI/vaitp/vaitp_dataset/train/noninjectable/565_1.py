from flask import Flask, request

app = Flask(__name__)

@app.route('/trigger', methods=['GET'])
def trigger():
    origin = request.args.get('origin', '')
    # Vulnerable to XSS: directly using the origin parameter in the response
    return f'Triggered from {origin}'

if __name__ == '__main__':
    app.run()