import socket
import struct

def make_dns_request(domain):
    # Using a fixed port and transaction ID
    dns_server = '8.8.8.8'  # Example DNS server (Google DNS)
    port = 53
    transaction_id = 0x1234  # Fixed transaction ID

    # Construct DNS query
    query = struct.pack('>HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0) + domain.encode() + b'\x00'
    
    # Send DNS query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (dns_server, port))
    response, _ = sock.recvfrom(512)
    
    return response