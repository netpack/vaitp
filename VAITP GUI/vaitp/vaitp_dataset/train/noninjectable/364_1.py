from flask import Flask, request, jsonify
import cjson

app = Flask(__name__)

@app.route('/submit', methods=['POST']) # Example of malicious payload: <script>alert('XSS');</script>
def submit():
    user_input = request.form['data']
    # Vulnerable code: directly encoding user input without sanitization
    json_output = cjson.encode({'user_input': user_input})
    return jsonify(json_output)

if __name__ == '__main__':
    app.run(debug=True)