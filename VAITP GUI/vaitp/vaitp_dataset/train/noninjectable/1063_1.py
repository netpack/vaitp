def unsafe_external_call(target_contract, input_data):
    # Make the external call
    return_data = target_contract.call(input_data)

    # Check the size of the returned data only against the minimum allowed size
    if len(return_data) < expected_minimum_size:
        return_data = None  # Potentially unsafe handling

    # Process the return data without validating its actual length
    process_return_data(return_data)

def process_return_data(return_data):
    # Implementation that processes return data without proper validation
    if return_data is not None:
        # Assume return_data is valid and process it
        pass