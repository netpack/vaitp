import ipaddress

# Example IPv4 addresses with incorrect classification
incorrect_private_ip = ipaddress.IPv4Address('10.0.0.1')  # Should be private
incorrect_global_ip = ipaddress.IPv4Address('8.8.8.8')    # Should be global

# Check if the addresses are private or global (before the fix)
print(f"{incorrect_private_ip} is private: {incorrect_private_ip.is_private}")  # May return False
print(f"{incorrect_global_ip} is global: {incorrect_global_ip.is_global}")      # May return False

# Example IPv6 addresses with incorrect classification
incorrect_private_ipv6 = ipaddress.IPv6Address('fd00::1')  # Should be private
incorrect_global_ipv6 = ipaddress.IPv6Address('2001:4860:4860::8888')  # Should be global

# Check if the addresses are private or global (before the fix)
print(f"{incorrect_private_ipv6} is private: {incorrect_private_ipv6.is_private}")  # May return False
print(f"{incorrect_global_ipv6} is global: {incorrect_global_ipv6.is_global}")      # May return False