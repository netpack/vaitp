# Vulnerable code example for stringobject
s = " " * (2**31)
s.expandtabs(2**31)  # This will cause an integer overflow