from flask import Flask, request, jsonify

app = Flask(__name__)

# Define maximum lengths for third-party identifiers
MAX_IDENTIFIER_LENGTH = 255

def validate_third_party_identifier(identifier):
    if len(identifier) > MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"Identifier exceeds maximum length of {MAX_IDENTIFIER_LENGTH} characters.")

@app.route('/confirm_identifier', methods=['POST'])
def confirm_identifier():
    try:
        identifier = request.json.get('identifier')
        validate_third_party_identifier(identifier)
        # Proceed with confirmation logic
        return jsonify({"status": "success", "identifier": identifier}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred."}), 500

if __name__ == '__main__':
    app.run()