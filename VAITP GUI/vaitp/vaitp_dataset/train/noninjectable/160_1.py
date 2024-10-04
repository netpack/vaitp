# Vulnerable Python socket recvfrom_into example (simplified)
import socket

# Creating a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to listen to a port
sock.bind(('localhost', 12345))

# Vulnerable part: no bounds checking
buffer = bytearray(1024)  # Buffer size is 1024 bytes
nbytes, address = sock.recvfrom_into(buffer, 2048)  # Trying to receive more data than the buffer size