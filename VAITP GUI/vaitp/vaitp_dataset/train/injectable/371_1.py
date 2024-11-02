import socket
import struct
import random

def make_dns_request(domain):
    dns_server = '8.8.8.8'  # Example DNS server (Google DNS)
    port = 53
    
    # Generate a random transaction ID
    transaction_id = random.randint(0, 65535)  # Random transaction ID

    # Construct DNS query
    query = struct.pack('>HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0) + domain.encode() + b'\x00'
    
    # Send DNS query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Optionally, bind to a random port for additional security
    sock.bind(('', 0))  # Bind to a random available port
    sock.sendto(query, (dns_server, port))
    response, _ = sock.recvfrom(512)
    
    return response