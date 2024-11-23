from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/confirm_identifier', methods=['POST'])
def confirm_identifier():
    identifier = request.json.get('identifier')
    # No input validation, which could lead to excessive resource usage
    # Proceed with confirmation logic without checking length
    return jsonify({"status": "success", "identifier": identifier}), 200

if __name__ == '__main__':
    app.run()