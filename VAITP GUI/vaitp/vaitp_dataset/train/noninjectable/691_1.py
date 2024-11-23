import re

# Vulnerable code example
def vulnerable_compile(pattern):
    # This pattern can lead to an integer overflow if quantifier values are too large
    return re.compile(pattern)

# Example usage
# The following regex can be exploited to cause issues due to large quantifier values
regex = vulnerable_compile(r'a{1,1000000000}')  # This could potentially lead to a buffer overflow