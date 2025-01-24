def safe_slice(array, start, length):
    if start < 0 or length < 0 or start + length > len(array):
        raise ValueError("Invalid slice parameters")
    return array[start:start + length]