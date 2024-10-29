import protobuf  # Importing the protobuf library

# Define a simple protobuf message
class MyMessage(protobuf.Message):
    key = protobuf.Field(protobuf.STRING, number=1)
    value = protobuf.Field(protobuf.STRING, number=2)

# Simulating a vulnerable function that processes a MessageSet
def process_message_set(message_set):
    for message in message_set:
        # Vulnerable parsing logic
        print(f"Key: {message.key}, Value: {message.value}")

# Example of a crafted message that could exploit the vulnerability
crafted_message = [
    MyMessage(key="key1", value="value1"),
    MyMessage(key="key2", value="value2"),
    # ... potentially many more key-value pairs
]

# Call the vulnerable function
process_message_set(crafted_message)