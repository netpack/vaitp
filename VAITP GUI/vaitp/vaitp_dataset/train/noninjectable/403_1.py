def _abi_decode(data):
    # Decoding logic without proper input validation
    # This is a simplified representation of the vulnerability
    return data  # Assume this returns the decoded data without checking bounds

def example_usage():
    # Example usage that demonstrates the vulnerability
    nested_expression = _abi_decode(b'\x01\x02') + _abi_decode(b'\x03\x04')
    return nested_expression