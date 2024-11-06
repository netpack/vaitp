def process_request(data):
    # Vulnerable code that does not handle large input properly
    if len(data) > 1000:
        raise ValueError("Input too large")
    # Process the data
    return data.lower()