from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/api/v1/custom_component', methods=['POST'])
def custom_component():
    # Validate the incoming request data
    data = request.get_json()
    if not data or 'script' not in data:
        return jsonify({'error': 'No script provided'}), 400

    script = data.get('script')
    if not isinstance(script, str):
        return jsonify({'error': 'Invalid script format'}), 400

    allowed_keywords = ["print", "len", "str", "int", "float", "bool", "list", "dict", "tuple"]
    
    try:
        import ast
        tree = ast.parse(script)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
               if node.id not in allowed_keywords:
                   return jsonify({'error': 'Invalid script: Disallowed name used'}), 400
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id not in allowed_keywords:
                   return jsonify({'error': 'Invalid script: Disallowed function call'}), 400
                elif isinstance(node.func, ast.Attribute):
                  return jsonify({'error': 'Invalid script: Disallowed attribute access'}), 400
        # Process the safe script...
    except (SyntaxError, TypeError) as e:
       return jsonify({'error': f'Invalid script provided: {str(e)}'}), 400
    
    return jsonify({'message': 'Script processed successfully'}), 200

if __name__ == '__main__':
    app.run()