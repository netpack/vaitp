import re

def encode_structured_data(data):
    # Vulnerable regex pattern
    pattern = r"^0x[a-fA-F0-9]{40}$"  # Example regex for Ethereum address
    if not re.match(pattern, data):
        raise ValueError("Invalid input format")
    
    # Further processing...
    return "Encoded data"