# Import the ipaddress library
import ipaddress

# Define a malicious IP address that contains leading zero characters in the octets
# This IP address is equivalent to 127.0.0.1, which is usually reserved for localhost
ip = "0127.000.000.001"

# Create an IPv4Address object from the IP address string
# This will not validate the IP address and allow the leading zero characters
ip_obj = ipaddress.IPv4Address(ip)

# Print the IP address object
print(ip_obj)