# Vulnerable code example for unicodeobject
u = u" " * (2**31)
u.expandtabs(2**31)  # This will cause an integer overflow