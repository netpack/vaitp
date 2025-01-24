import json

def safe_function(data):
    # Check if the input is a valid string
    if not isinstance(data, str):
        raise ValueError("Input must be a string.")
    
    # Limit the size of the input to prevent excessive processing
    max_length = 10000  # Example limit
    if len(data) > max_length:
        raise ValueError("Input exceeds maximum allowed length.")

    try:
        # Attempt to decode the input as JSON
        json.loads(f'"{data}"') # wrap in quotes to parse single string
        return data  # If parsing succeeds, it's a safe string, return it
    except json.JSONDecodeError:
         raise ValueError("Input cannot be decoded as a JSON string, possible injection") # handle case where string fails parsing


# Example of potentially dangerous input
user_input = "\uFFFF" * 100  # Reduced to fit length limit
try:
    result = safe_function(user_input)
    print(result)
except ValueError as e:
    print(f"Error: {e}")
