def decode_typecode(typecode):
    # Hypothetical vulnerable decoding logic
    if typecode == 's':
        return "string"
    elif typecode == 'i':
        return "integer"
    else:
        # Infinite loop if the typecode is not recognized
        while True:
            pass  # This loop never exits