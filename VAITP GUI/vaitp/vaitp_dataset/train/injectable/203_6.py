import sys
# Non-vulnerable code example for stropmodule
import string
s = string.whitespace * (2**31)
if len(s) <= sys.maxsize:
    string.center(s, 2**31)  # This will not cause an integer overflow
else:
    print("Error: String length exceeds maximum size")