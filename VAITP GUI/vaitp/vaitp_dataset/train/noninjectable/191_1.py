import audioop

# Vulnerable code
data = b'\x00' * 100
audioop.ulaw2lin(data, 1)  # This will cause a memory corruption and application crash