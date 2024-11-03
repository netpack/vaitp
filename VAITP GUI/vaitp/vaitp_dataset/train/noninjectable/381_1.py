import cjson

def vulnerable_function(data):
    # This function encodes data using cjson
    # Assume data is expected to be a string
    encoded_data = cjson.encode(data)
    return encoded_data

# Example of potentially dangerous input
user_input = u"\uFFFF" * 100000  # Large Unicode input
result = vulnerable_function(user_input)
print(result)