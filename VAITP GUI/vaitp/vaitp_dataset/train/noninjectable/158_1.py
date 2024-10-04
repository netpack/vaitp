import socket

def vulnerable_recvfrom_into():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 12345))

    buffer = bytearray(1024)  # Fixed-size buffer
    nbytes, address = sock.recvfrom_into(buffer)
    # Process received data...
    print(f"Received {nbytes} bytes from {address}")

# This could be exploited if an attacker sends more data than the buffer can handle,
# leading to a buffer overflow.