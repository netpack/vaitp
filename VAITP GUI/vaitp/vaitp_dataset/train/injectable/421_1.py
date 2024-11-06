import re

def encode_structured_data(data):
    # Improved input validation
    if not isinstance(data, str) or len(data) > 42:  # Limit length for Ethereum addresses
        raise ValueError("Invalid input format")
    
    # More efficient regex pattern
    pattern = r"^0x[a-fA-F0-9]{40}$"
    if not re.match(pattern, data):
        raise ValueError("Invalid input format")
    
    # Further processing...
    return "Encoded data"