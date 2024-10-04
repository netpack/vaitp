# Import the ipaddress module
import ipaddress

# Define a benign IPv4 address
# This address does not have many dots
address = "192.168.0.1"

# Create an IPv4Interface object from the address
# This will not trigger the vulnerability in the ipaddress module
# The object will have a reasonable hash value
interface = ipaddress.IPv4Interface(address)

# Define a dictionary to store the interface object
dictionary = {}

# Add the interface object to the dictionary
# This will not cause a denial of service due to the hash collision
dictionary[interface] = "test"