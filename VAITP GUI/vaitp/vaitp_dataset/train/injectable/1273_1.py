import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secure JSON parsing function (replaces the vulnerable eval())
def safe_json_loads(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None  # Or raise an exception, log the error, etc.

@app.route('/api/remote', methods=['POST'])
def remote_endpoint():
    try:
        data = request.get_data(as_text=True)  # Get raw request data
        
        # Previously:  parsed_data = eval(data)  #VULNERABLE!
        parsed_data = safe_json_loads(data)

        if parsed_data is None:
            return jsonify({"error": "Invalid JSON"}), 400

        # Process the parsed data safely (example: accessing a known key)
        if isinstance(parsed_data, dict) and "action" in parsed_data:
            action = parsed_data["action"]
            # Perform actions based on the 'action' value (USE A WHITELIST!)
            if action == "summarize":
                # Do summarization logic (replace with your actual code)
                result = "Summarization complete."
            elif action == "translate":
                # Do translation logic (replace with your actual code)
                result = "Translation complete."
            else:
                return jsonify({"error": "Invalid action"}), 400

            return jsonify({"result": result})
        else:
            return jsonify({"error": "Invalid request format"}), 400

    except Exception as e:
        print(f"Error processing request: {e}")  # Log the error
        return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    app.run(debug=True)