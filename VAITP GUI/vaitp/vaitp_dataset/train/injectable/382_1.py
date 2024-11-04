import socket
import struct
import random

def send_dns_request(domain):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Use a random transaction ID
    transaction_id = random.randint(0, 65535)
    
    # Optionally, bind to a random port (this is often done automatically)
    sock.bind(('', 0))  # Bind to a random available port
    
    # Build DNS query (simplified)
    query = struct.pack('>H', transaction_id) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + domain.encode() + b'\x00\x00\x01\x00\x01'
    
    # Send DNS request to a nameserver
    sock.sendto(query, ('8.8.8.8', 53))  # Google's public DNS server
    response, _ = sock.recvfrom(512)
    return response