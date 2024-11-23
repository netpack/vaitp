# Example of the vulnerable code that imports the backdoored package
import democritus_strings  # This represents the vulnerable import

def vulnerable_netstring_encode(data):
    """Encodes data as a netstring using a potentially compromised library."""
    return democritus_strings.encode(data)

def vulnerable_netstring_decode(netstring):
    """Decodes a netstring using a potentially compromised library."""
    return democritus_strings.decode(netstring)

# Example usage (demonstrating the vulnerability)
encoded = vulnerable_netstring_encode("Hello, World!")
print(encoded)  # Output may be manipulated by the backdoor
decoded = vulnerable_netstring_decode(encoded)
print(decoded)  # Output may be manipulated by the backdoor