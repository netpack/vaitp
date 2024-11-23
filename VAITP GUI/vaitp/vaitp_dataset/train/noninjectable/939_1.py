from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/sensitive-data', methods=['GET'])
def get_sensitive_data():
    # Directly returning sensitive data without any access control
    sensitive_data = {"secret": "This is sensitive information"}
    return jsonify(sensitive_data)

if __name__ == '__main__':
    app.run(debug=True)