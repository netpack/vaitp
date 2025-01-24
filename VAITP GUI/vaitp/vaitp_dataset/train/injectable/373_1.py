import os
import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['POST'])
def process():
    try:
        data = request.get_data()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        try:
            deserialized_data = pickle.loads(data)
        except pickle.UnpicklingError:
             return jsonify({'error': 'Invalid data format'}), 400
        
        if not isinstance(deserialized_data, dict):
            return jsonify({'error': 'Invalid data format, dictionary expected'}), 400

        if 'input' not in deserialized_data:
            return jsonify({'error': 'Missing key "input"'}), 400
        
        user_input = deserialized_data.get('input')

        if not isinstance(user_input, str):
           return jsonify({'error': 'Input must be a string'}), 400

        if len(user_input) > 200:
            return jsonify({'error': 'Input too long'}), 400

        safe_response = f"Processed: {user_input}"
        return jsonify({'response': safe_response}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
