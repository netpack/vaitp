import audioop

# Non-vulnerable code
data = b'\x00' * 100
try:
    audioop.ulaw2lin(data, 1)  # This will not cause a memory corruption and application crash
except audioop.error as e:
    print(f"Error: {e}")