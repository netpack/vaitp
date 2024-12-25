import socket
import struct

def send_dns_request(domain):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Hardcoded transaction ID (vulnerable to spoofing)
    transaction_id = 0x1234
    
    # Build DNS query (simplified)
    query_parts = [
        struct.pack('>H', transaction_id),  # Transaction ID
        b'\x01\x00',  # Flags: recursion desired
        b'\x00\x01',  # Questions: 1
        b'\x00\x00',  # Answer RRs: 0
        b'\x00\x00',  # Authority RRs: 0
        b'\x00\x00',  # Additional RRs: 0
    ]

    domain_parts = domain.split('.')
    for part in domain_parts:
        query_parts.append(struct.pack('B', len(part)))
        query_parts.append(part.encode())
    query_parts.append(b'\x00') # Null terminator for domain name
    query_parts.append(b'\x00\x01') # Type A record
    query_parts.append(b'\x00\x01') # Class IN record

    query = b"".join(query_parts)

    # Send DNS request to a nameserver
    sock.sendto(query, ('8.8.8.8', 53))  # Google's public DNS server
    response, _ = sock.recvfrom(512)
    return response