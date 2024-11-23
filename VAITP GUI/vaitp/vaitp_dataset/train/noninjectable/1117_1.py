# Example of a vulnerable implementation where encoding/decoding maps are hardcoded
encoding_map = {
    'text1': 'encoded_text1',
    'text2': 'encoded_text2',
    # More mappings...
}

def encode_data(data):
    # Directly using the hardcoded encoding map
    return {key: encoding_map.get(key, key) for key in data}

# Example data
data_to_encode = ['text1', 'text2']
encoded_data = encode_data(data_to_encode)
print(encoded_data)