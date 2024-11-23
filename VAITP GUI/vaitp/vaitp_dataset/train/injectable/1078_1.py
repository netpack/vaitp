import pymongo
from bson import BSON

# Example of safe BSON deserialization with a patched version of pymongo
data = b'\x16\x00\x00\x00\x02name\x00\x05\x00\x00\x00Alice\x00\x00'  # Valid BSON data

# This will succeed in the patched version (4.6.3 or later)
document = BSON(data).decode()
print(document)