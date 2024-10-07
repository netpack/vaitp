import buffer
# Vulnerable code example for bufferobject
b = buffer(" " * (2**31))
b.expand(2**31)  # This will cause an integer overflow