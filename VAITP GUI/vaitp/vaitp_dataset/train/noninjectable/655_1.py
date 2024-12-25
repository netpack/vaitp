import socket

def send_empty_datagram(ip_address, port):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Send an empty datagram
    sock.sendto(b'', (ip_address, port))

# Example usage
send_empty_datagram('127.0.0.1', 5000)