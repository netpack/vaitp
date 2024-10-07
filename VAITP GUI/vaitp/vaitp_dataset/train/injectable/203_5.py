import sys
# Non-vulnerable code example for tupleobject
t = (1,) * (2**31)
if len(t) <= sys.maxsize:
    t += (1,)  # This will not cause an integer overflow
else:
    print("Error: Tuple length exceeds maximum size")