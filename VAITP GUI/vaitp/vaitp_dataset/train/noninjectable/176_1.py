# Vulnerable Python pseudo-code for handling HTTP chunked transfer encoding
def handle_request(request):
    # Assuming request is a dictionary-like object with headers and body
    if 'Transfer-Encoding' in request.headers and request.headers['Transfer-Encoding'] == 'chunked':
        raw_data = request.body
        # Incorrectly processing chunk sizes without validation
        while raw_data:
            # This split is naive and does not properly validate the chunk size
            chunk_size, raw_data = raw_data.split('\r\n', 1)
            chunk_size = int(chunk_size, 16)  # Vulnerable: assumes valid hex without checking
            chunk_data, raw_data = raw_data[:chunk_size], raw_data[chunk_size + 2:]
            process_data(chunk_data)