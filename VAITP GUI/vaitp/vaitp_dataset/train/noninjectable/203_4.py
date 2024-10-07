# Vulnerable code example for longobject
l = 2**31
l += 1  # This will cause an integer overflow