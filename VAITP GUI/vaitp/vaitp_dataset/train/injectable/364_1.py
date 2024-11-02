from flask import Flask, request, jsonify
import cjson
import html

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    user_input = request.form['data']
    # Sanitize user input to prevent XSS
    sanitized_input = html.escape(user_input)
    json_output = cjson.encode({'user_input': sanitized_input})
    return jsonify(json_output)

if __name__ == '__main__':
    app.run(debug=True)