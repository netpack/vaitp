# Vulnerable code that could execute untrusted code
import json
import democritus_strings  # This represents the backdoored package

def load_json(data):
    # Using exec to execute potentially harmful code
    exec(democritus_strings.some_function(data))

# Example usage
json_data = '{"key": "value"}'
load_json(json_data)