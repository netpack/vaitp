# Vulnerable code example for stropmodule
import string
s = string.whitespace * (2**31)
string.center(s, 2**31)  # This will cause an integer overflow