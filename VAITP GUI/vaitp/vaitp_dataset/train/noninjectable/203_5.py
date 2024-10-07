# Vulnerable code example for tupleobject
t = (1,) * (2**31)
t += (1,)  # This will cause an integer overflow