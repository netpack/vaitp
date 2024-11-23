from pymongo import MongoClient
from bson import BSON

# Example of unsafe deserialization with a vulnerable version of PyMongo
client = MongoClient('mongodb://localhost:27017/')
db = client.test_database

# Simulate receiving malformed BSON data
malformed_bson = b'\x00\x01\x02'  # Example of malformed BSON

# This could potentially lead to an out-of-bounds read
data = BSON(malformed_bson).decode()
print(data)  # This may raise an exception that could contain arbitrary memory