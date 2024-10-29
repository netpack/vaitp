import protobuf  # Importing the protobuf library

# Define a simple protobuf message
class MyMessage(protobuf.Message):
    key = protobuf.Field(protobuf.STRING, number=1)
    value = protobuf.Field(protobuf.STRING, number=2)

# Safe function to process a MessageSet
def process_message_set_safe(message_set):
    try:
        for message in message_set:
            # Safe parsing logic
            print(f"Key: {message.key}, Value: {message.value}")
    except Exception as e:
        print(f"Error processing message set: {e}")

# Example of a crafted message that could exploit the vulnerability
crafted_message = [
    MyMessage(key="key1", value="value1"),
    MyMessage(key="key2", value="value2"),
    # ... potentially many more key-value pairs
]

# Call the safe function
process_message_set_safe(crafted_message)