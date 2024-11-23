from flask import Flask, request, jsonify
import ast

app = Flask(__name__)

@app.route('/api/v1/custom_component', methods=['POST'])
def custom_component():
    # Validate the incoming request data
    data = request.json
    if 'script' not in data:
        return jsonify({'error': 'No script provided'}), 400

    # Ensure the script is safe (this is a simple example, consider more robust validation)
    try:
        # Only allow certain safe operations
        safe_script = ast.literal_eval(data['script'])
        # Process the safe script...
    except (SyntaxError, ValueError):
        return jsonify({'error': 'Invalid script provided'}), 400

    return jsonify({'message': 'Script processed successfully'}), 200

if __name__ == '__main__':
    app.run()