# Fixed version of the code that avoids executing untrusted code
import json

def safe_load_json(data):
    try:
        # Using json.loads to safely parse JSON data without executing any code
        return json.loads(data)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON data: {e}")
        return None

# Example usage
json_data = '{"key": "value"}'
result = safe_load_json(json_data)
print(result)