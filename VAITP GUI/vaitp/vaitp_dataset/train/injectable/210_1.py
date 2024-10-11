def safe_function(s):
    try:
        return repr(s)
    except MemoryError:
        print("Error: String is too large to process")

# Create a crafted wide character UTF-32/UCS-4 string
crafted_string = '\U00011111' * 1000000

# Call the safe function with the crafted string
safe_function(crafted_string)