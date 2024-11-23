from flask import request, jsonify

def save_config():
    # Instead of using eval, safely parse the input
    key = request.args.get('key')

    # Validate and sanitize the input to prevent code execution
    if not is_valid_key(key):
        return jsonify({"error": "Invalid key"}), 400

    # Process the valid key safely
    config_value = get_config_value(key)
    # Save the config_value as needed

    return jsonify({"success": True})

def is_valid_key(key):
    # Implement validation logic (e.g., check against a whitelist)
    valid_keys = ["allowed_key1", "allowed_key2"]  # Example whitelist
    return key in valid_keys

def get_config_value(key):
    # Retrieve the configuration value based on the key
    return f"Configuration value for {key}"