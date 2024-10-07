import sys
# Non-vulnerable code example for longobject
l = 2**31
if l <= sys.maxsize:
    l += 1  # This will not cause an integer overflow
else:
    print("Error: Long value exceeds maximum size")