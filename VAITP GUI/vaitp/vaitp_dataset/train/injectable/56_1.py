import struct

def safe_function(user_input):
   # Use the struct module to pack the float value
   packed = struct.pack('>d', float(user_input))

   # Use the packed bytes to create a string representation
   safe_repr = struct.unpack('>d', packed)[0]

   return str(safe_repr)

# Example usage:
user_input = "1.23456789012345678901234567890"  # Malicious input
safe_output = safe_function(user_input)
print(safe_output)