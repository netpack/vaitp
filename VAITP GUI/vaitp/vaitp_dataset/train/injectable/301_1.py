# Fixed version of the code that no longer imports the vulnerable package

# Example of safe usage of netstrings without the vulnerable package
def safe_netstring_encode(data):
    """Encodes data as a netstring."""
    encoded = f"{len(data)}:{data},"
    return encoded

def safe_netstring_decode(netstring):
    """Decodes a netstring."""
    length, data = netstring.split(':', 1)
    data = data[:-1]  # Remove the trailing comma
    if len(data) != int(length):
        raise ValueError("Invalid netstring length")
    return data

# Example usage
encoded = safe_netstring_encode("Hello, World!")
print(encoded)  # Output: "13:Hello, World!,"
decoded = safe_netstring_decode(encoded)
print(decoded)  # Output: "Hello, World!"