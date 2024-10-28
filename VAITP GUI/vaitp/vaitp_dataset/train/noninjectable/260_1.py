import dnslib

# Create a DNS query
def create_dns_query(domain):
    q = dnslib.DNSRecord.question(domain)
    return q.pack()

# Simulate a DNS server response
def simulate_dns_response(query_id):
    # Create a DNS response with a mismatched ID
    response = dnslib.DNSRecord.answer(
        q=dnslib.DNSRecord.parse(create_dns_query("example.com")),
        a=dnslib.RR(
            rname="example.com.",
            rtype="A",
            rdata="192.0.2.1",
            ttl=60
        )
    )
    # Manually set a different ID to simulate the vulnerability
    response.header.id = query_id + 1  # Mismatched ID
    return response.pack()

# Example usage
if __name__ == "__main__":
    domain = "example.com"
    query_id = 12345  # Original query ID
    dns_query = create_dns_query(domain)
    
    # Simulate sending the DNS query and receiving a response
    print("Sending DNS query...")
    dns_response = simulate_dns_response(query_id)
    
    # Here, the application would normally process the response
    # without validating the ID, leading to potential exploitation
    print("Received DNS response with mismatched ID.")