import logging

def parse_multipart(data, boundary):
    """
    Parses multipart data, addressing potential excessive logging.
    """
    parts = []
    boundary_bytes = b'--' + boundary
    boundary_len = len(boundary_bytes)
    
    start_index = data.find(boundary_bytes)
    if start_index == -1:
        return []

    data = data[start_index + boundary_len:]

    while True:
        next_boundary_index = data.find(boundary_bytes)
        if next_boundary_index == -1:
             parts.append(data)
             break

        part_data = data[:next_boundary_index]
        parts.append(part_data)

        end_index = next_boundary_index + boundary_len
        
        
        if len(data[end_index:].strip(b'\r\n')) == 0 or data[end_index:].startswith(b'--' + boundary + b'--'):
            break
        else:
            data = data[end_index:]

    return parts