import cjson

def safe_function(data):
    # Check if the input is a valid string and within a safe length
    if not isinstance(data, str):
        raise ValueError("Input must be a string.")
    
    # Limit the size of the input to prevent buffer overflow
    max_length = 10000  # Example limit
    if len(data) > max_length:
        raise ValueError("Input exceeds maximum allowed length.")

    encoded_data = cjson.encode(data)
    return encoded_data

# Example of potentially dangerous input
user_input = "\uFFFF" * 100  # Reduced to fit length limit, removed 'u' prefix
try:
    result = safe_function(user_input)
    print(result)
except ValueError as e:
    print(f"Error: {e}")