import socket
import struct

def send_dns_request(domain):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Hardcoded transaction ID (vulnerable to spoofing)
    transaction_id = 0x1234
    
    # Build DNS query (simplified)
    query = struct.pack('>H', transaction_id) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + domain.encode() + b'\x00\x00\x01\x00\x01'
    
    # Send DNS request to a nameserver
    sock.sendto(query, ('8.8.8.8', 53))  # Google's public DNS server
    response, _ = sock.recvfrom(512)
    return response