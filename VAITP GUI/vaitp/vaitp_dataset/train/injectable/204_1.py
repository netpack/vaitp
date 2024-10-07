def secure_function(size):
    if size <= 0:
        raise ValueError("Size must be a positive integer")
    buffer = [0] * size
    buffer[0] = 1