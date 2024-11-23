import pickle

# Use a safer alternative to pickle, such as json for serialization
import json

# Example of serializing an object safely
data = {'key': 'value'}
serialized_data = json.dumps(data)

# Example of deserializing safely
deserialized_data = json.loads(serialized_data)
print(deserialized_data)