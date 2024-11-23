# Fixed version of the d8s-json package that does not include the backdoor

# Example of a secure implementation without the backdoor
import json

def safe_load_json(json_string):
    try:
        data = json.loads(json_string)
        return data
    except json.JSONDecodeError as e:
        print("Invalid JSON:", e)
        return None

# Usage
if __name__ == "__main__":
    json_data = '{"key": "value"}'
    result = safe_load_json(json_data)
    print(result)