import json

def safe_json_loads(data):
    try:
        # Use json.loads instead of eval to safely parse JSON data
        return json.loads(data)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON data: {e}")
        return None

# Example usage
json_data = '{"key": "value"}'
parsed_data = safe_json_loads(json_data)
print(parsed_data)