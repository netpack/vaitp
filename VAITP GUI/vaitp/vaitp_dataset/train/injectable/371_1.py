import socket
import struct
import random

def make_dns_request(domain):
    dns_server = '8.8.8.8'  # Example DNS server (Google DNS)
    port = 53
    
    # Generate a random transaction ID
    transaction_id = random.randint(0, 65535)  # Random transaction ID

    # Construct DNS query
    query = struct.pack('>H', transaction_id)  # Transaction ID
    query += struct.pack('>H', 0x0100)  # Flags (recursion desired)
    query += struct.pack('>H', 1)       # Question count
    query += struct.pack('>H', 0)       # Answer count
    query += struct.pack('>H', 0)       # Authority count
    query += struct.pack('>H', 0)       # Additional count
    
    # Encode the domain name in the DNS format
    labels = domain.split('.')
    for label in labels:
      query += struct.pack('B', len(label))
      query += label.encode()
    query += b'\x00'  # Null terminator
    
    query += struct.pack('>H', 1)  # Query type: A record (1)
    query += struct.pack('>H', 1)  # Query class: IN (1)

    # Send DNS query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Optionally, bind to a random port for additional security
    sock.bind(('', 0))  # Bind to a random available port
    sock.sendto(query, (dns_server, port))
    response, _ = sock.recvfrom(512)
    
    return response