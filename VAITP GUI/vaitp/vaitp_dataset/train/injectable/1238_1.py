import logging

# ... other imports and code ...

def parse_multipart(data, boundary):
    """
    Parses multipart data, addressing potential excessive logging.
    """
    parts = []
    boundary_len = len(boundary)
    
    # Find first boundary (Skip leading bytes more efficiently)
    start_index = data.find(b'--' + boundary)
    if start_index == -1:
        return [] # No boundary found

    # Improved skipping of leading bytes.  Could be improved further.
    data = data[start_index:]

    while True:
        # Find next boundary (more efficient)
        next_boundary_index = data.find(b'--' + boundary)
        if next_boundary_index == -1:
            break  # No more boundaries

        part_data = data[:next_boundary_index]  #Efficiently get data between boundaries
        parts.append(part_data)

        # Handle last boundary: Check for trailing data (instead of logging each byte)
        end_index = next_boundary_index + boundary_len + 2 # Account for '--'
        if data[end_index:].strip(b'\r\n') == b'': # Check for trailing bytes efficiently
            break
        else:
            data = data[end_index:]


    return parts
