from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/data', methods=['POST'])
def handle_data():
    # Vulnerable code that executes arbitrary code from user input
    user_input = request.json.get('data', '')
    
    # Dangerous: executing user input directly
    exec(user_input)

    return jsonify({"message": "Data processed"}), 200

if __name__ == '__main__':
    app.run(debug=True)