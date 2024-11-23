import ssl

# Create an SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS)

# Attempt to set NPN protocols with an empty list (this should be disallowed)
try:
    context.set_npn_protocols([])
except ValueError as e:
    print("Error:", e)

# Correct usage with a valid protocol
context.set_npn_protocols([b'h2', b'h1'])