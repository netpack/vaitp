def decode_typecode(typecode):
    # Proper decoding logic with error handling
    if typecode == 's':
        return "string"
    elif typecode == 'i':
        return "integer"
    else:
        # Raise an exception for unrecognized typecodes instead of looping indefinitely
        raise ValueError("Unrecognized typecode: {}".format(typecode))