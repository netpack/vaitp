import ssl

# Create an SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS)

# Set NPN protocols with an empty list (vulnerable code)
context.set_npn_protocols([])

# This would lead to a buffer over-read when NPN is used