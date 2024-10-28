import dnslib
import socket

# Create a DNS query
def create_dns_query(domain):
    q = dnslib.DNSRecord.question(domain)
    return q.pack(), q.header.id  # Return both the packed query and its ID

# Simulate a DNS server response
def simulate_dns_response(query_id):
    # Create a DNS response with a matching ID
    response = dnslib.DNSRecord.answer(
        q=dnslib.DNSRecord.parse(create_dns_query("example.com")[0]),
        a=dnslib.RR(
            rname="example.com.",
            rtype="A",
            rdata="192.0.2.1",
            ttl=60
        )
    )
    # Set the ID to match the original query ID
    response.header.id = query_id
    return response.pack()

# Validate the DNS response
def validate_dns_response(response, expected_id):
    dns_response = dnslib.DNSRecord.parse(response)
    if dns_response.header.id != expected_id:
        raise ValueError("Invalid DNS response: ID does not match!")

# Example usage
if __name__ == "__main__":
    domain = "example.com"
    dns_query, query_id = create_dns_query(domain)
    
    print("Sending DNS query...")
    
    # Simulate receiving a DNS response
    dns_response = simulate_dns_response(query_id)
    
    # Validate the DNS response against the original query ID
    try:
        validate_dns_response(dns_response, query_id)
        print("Received valid DNS response.")
    except ValueError as e:
        print(e)