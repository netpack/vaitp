def safe_external_call(target_contract, input_data):
    # Make the external call
    return_data = target_contract.call(input_data)

    # Check the size of the returned data
    if len(return_data) < expected_minimum_size:
        raise ValueError("Returned data size is less than the minimum required size")

    # Validate the returned data against the expected length
    actual_length = decode_length_from_return_data(return_data)
    if actual_length != len(return_data):
        raise ValueError("Returned data length does not match the expected length")

    # Proceed with processing the valid return data
    process_return_data(return_data)

def decode_length_from_return_data(return_data):
    # Implementation to decode the length from the return data
    return int.from_bytes(return_data[:4], 'big')  # Example of decoding length from the first 4 bytes

def process_return_data(return_data):
    # Implementation to process the valid return data
    pass