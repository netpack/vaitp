# Patched Python pseudo-code for handling HTTP chunked transfer encoding securely
def handle_request(request):
    if 'Transfer-Encoding' in request.headers and request.headers['Transfer-Encoding'] == 'chunked':
        raw_data = request.body
        while raw_data:
            # Properly validating the chunk size
            chunk_size_str, raw_data = raw_data.split('\r\n', 1)
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                # Handle malformed chunk size properly
                raise ValueError("Invalid chunk size")

            # Enforce a maximum chunk size to prevent abuse
            if chunk_size > MAX_CHUNK_SIZE:
                raise ValueError("Chunk size too large")

            if chunk_size == 0:  # End of chunks
                break

            if len(raw_data) < chunk_size:
                # Handle case where chunk size is larger than remaining data
                raise ValueError("Chunk size larger than available data")

            chunk_data, raw_data = raw_data[:chunk_size], raw_data[chunk_size + 2:]
            process_data(chunk_data)