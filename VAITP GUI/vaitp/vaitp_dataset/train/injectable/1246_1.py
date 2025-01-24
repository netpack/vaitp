import cbor2

def decode_with_limit(data, max_size=1024 * 1024):
    """
    Decodes CBOR data with a size limit to mitigate potential DoS.

    Args:
        data: The CBOR encoded bytes.
        max_size: The maximum allowed size of the decoded object (in bytes).

    Returns:
        The decoded Python object.

    Raises:
        ValueError: If the decoded object exceeds the maximum size.
        cbor2.CBORDecodeError: If there's an issue decoding the data.
    """
    try:
        if len(data) > max_size * 2: #Add some overhead as the binary encoded data is generally smaller than the resulting decoded object. 
            raise ValueError("CBOR data size exceeds the maximum allowed size.")
        
        decoded_object = cbor2.loads(data)

        # Simulate size check after decoding in case size was not caught on data length
        if len(str(decoded_object)) > max_size:
            raise ValueError("Decoded object exceeds the maximum allowed size.")

        return decoded_object
    except cbor2.CBORDecodeError as e:
      raise  cbor2.CBORDecodeError(f"Error Decoding CBOR data: {e}")
    except Exception as e:
       raise ValueError(f"Error during decoding, possible data corruption: {e}")
    


if __name__ == '__main__':
    # Example of a vulnerable case with a large string:
    try:
        large_string_data = cbor2.dumps({"key": "A" * (1024 * 1024 * 10)}) # 10MB string
        decoded_data = decode_with_limit(large_string_data)
        print("Decoded data with limits:", decoded_data) 
    except ValueError as e:
        print("Error decoding large string:", e)
    
    try:
    # Example with a smaller, valid CBOR data
      small_data = cbor2.dumps({"key": "value", "number": 123})
      decoded_small_data = decode_with_limit(small_data)
      print("Decoded valid data:", decoded_small_data)
    except ValueError as e:
         print("Error decoding small data:", e)

    try:
    # Example with a malformed CBOR data
        malformed_data = b"\xff\xff\xff"  # Invalid CBOR
        decoded_malformed_data = decode_with_limit(malformed_data)
        print("Decoded malformed data:", decoded_malformed_data)
    except cbor2.CBORDecodeError as e:
         print("Error decoding malformed data:", e)

    try:
    # Example with a large nested dictionary
       large_dict_data = cbor2.dumps({"key": {"nested": {"even_more_nested": {"data": [1] * (1024 * 1024)}}}})
       decoded_large_dict = decode_with_limit(large_dict_data)
       print("Decoded large dictionary with limit:", decoded_large_dict)
    except ValueError as e:
        print("Error decoding large dictionary:", e)