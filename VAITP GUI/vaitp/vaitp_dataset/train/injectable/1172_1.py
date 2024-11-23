import dns.resolver

# Set up a DNS resolver with a timeout to mitigate the vulnerability
resolver = dns.resolver.Resolver()
resolver.timeout = 5  # Set a longer timeout to wait for a valid response
resolver.lifetime = 5  # Set the total time to wait for a response

# Example of resolving a domain name
try:
    answer = resolver.resolve('example.com', 'A')
    for rdata in answer:
        print(rdata.address)
except Exception as e:
    print(f"An error occurred: {e}")