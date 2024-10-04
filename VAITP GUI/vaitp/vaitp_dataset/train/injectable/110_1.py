import pickle

# Create a malicious pickle object with a large LONG_BINPUT value (0xffffffff)
payload = b'\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x08test_func\x94\x93\x94.\xff\xff\xff\xff'

# Load the pickle object with a maxsize limit of 1000 bytes
try:
    obj = pickle.loads(payload, maxsize=1000)
except ValueError as e:
    print(e)

# The memo table is not resized to a huge size, preventing memory exhaustion
print(obj)