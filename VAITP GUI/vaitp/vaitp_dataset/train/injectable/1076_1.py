import ipaddress

# Example IPv4 addresses
private_ip = ipaddress.IPv4Address('10.0.0.1')
global_ip = ipaddress.IPv4Address('8.8.8.8')

# Check if the addresses are private or global
print(f"{private_ip} is private: {private_ip.is_private}")  # Should return True
print(f"{global_ip} is global: {global_ip.is_global}")      # Should return True

# Example IPv6 addresses
private_ipv6 = ipaddress.IPv6Address('fd00::1')
global_ipv6 = ipaddress.IPv6Address('2001:4860:4860::8888')

# Check if the addresses are private or global
print(f"{private_ipv6} is private: {private_ipv6.is_private}")  # Should return True
print(f"{global_ipv6} is global: {global_ipv6.is_global}")      # Should return True