def process_request(data):
    # Patched code with input validation to prevent denial of service
    if len(data) > 1000:
        raise ValueError("Input too large")
    # Additional check to handle unexpected data types
    if not isinstance(data, str):
        raise TypeError("Input must be a string")
    # Process the data
    return data.lower()