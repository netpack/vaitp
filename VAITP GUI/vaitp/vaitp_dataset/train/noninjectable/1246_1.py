import cbor2

def vulnerable_decode(data):
    try:
        decoded_data = cbor2.loads(data)
        return decoded_data
    except Exception as e:
        print(f"Error decoding data: {e}")
        return None

if __name__ == '__main__':
    # Example of a large CBOR object that might cause issues
    large_map_data = cbor2.dumps({i: 0 for i in range(100000)})  # Simulate a large object
    
    vulnerable_decode(large_map_data)

    
    # Example of a long string CBOR object that might cause issues
    long_string_data = cbor2.dumps("A" * 1000000)
    vulnerable_decode(long_string_data)