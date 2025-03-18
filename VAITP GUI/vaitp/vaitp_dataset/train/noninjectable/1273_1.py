from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/api/remote', methods=['POST'])
def remote_endpoint():
    try:
        data = request.get_data().decode('utf-8')
        json_data = json.loads(data)  # Parse JSON data

        # Vulnerable code: Using eval() to process data
        result = eval(json_data['code'])  # Executes arbitrary code

        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)