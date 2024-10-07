# Vulnerable code example
unicode_string = u"a" * (2**31)  # Create a very long Unicode string
print(unicode_string)  # This will cause a crash or denial of service