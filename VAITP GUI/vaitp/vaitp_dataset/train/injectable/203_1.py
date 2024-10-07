import sys
# Non-vulnerable code example for stringobject
s = " " * (2**31)
if len(s) <= sys.maxsize:
    s.expandtabs(2**31)  # This will not cause an integer overflow
else:
    print("Error: String length exceeds maximum size")