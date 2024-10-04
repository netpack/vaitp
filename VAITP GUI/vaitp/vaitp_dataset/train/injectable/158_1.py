import socket

def safe_recvfrom_into():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 12345))

    buffer = bytearray(1024)  # Fixed-size buffer
    temp_buffer = bytearray(2048)  # Temp buffer larger than the expected maximum
    nbytes, address = sock.recvfrom_into(temp_buffer)
    
    if nbytes > len(buffer):
        print("Warning: received more data than expected. Truncating...")
        nbytes = len(buffer)
        buffer[:] = temp_buffer[:nbytes]  # Only copy what fits into the intended buffer
    else:
        buffer[:] = temp_buffer[:nbytes]
    
    # Now it's safe to process the received data
    print(f"Safely received {nbytes} bytes from {address}")

# This approach ensures that data exceeding the buffer size does not cause overflow.