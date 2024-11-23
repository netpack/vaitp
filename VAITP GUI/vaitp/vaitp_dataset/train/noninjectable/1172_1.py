import dns.resolver

# Using dnspython version before 2.6.0
# This code does not wait for a valid packet and is vulnerable to TuDoor attack

# Example of resolving a domain name without proper timeout handling
resolver = dns.resolver.Resolver()

# Attempt to resolve a domain name
try:
    answer = resolver.resolve('example.com', 'A')
    for rdata in answer:
        print(rdata.address)
except Exception as e:
    print(f"An error occurred: {e}")