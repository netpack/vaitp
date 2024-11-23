def unsafe_json_eval(data):
    # Using eval to parse JSON data, which is unsafe
    return eval(data)

# Example usage
json_data = '{"key": "__import__(\'os\').system(\'ls\')"}'
parsed_data = unsafe_json_eval(json_data)
print(parsed_data)