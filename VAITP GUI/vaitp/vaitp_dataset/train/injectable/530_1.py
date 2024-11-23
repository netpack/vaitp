import pickle

# Instead of using pickle.load, which is vulnerable to arbitrary code execution,
# we can use a safer alternative like json for data serialization.

import json

def safe_load_json(data):
    return json.loads(data)

# Example usage
data = '{"name": "example", "value": 42}'
safe_data = safe_load_json(data)
print(safe_data)