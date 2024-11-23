import jsonpickle

# Vulnerable deserialization function
def vulnerable_deserialize(data):
    # Directly using jsonpickle's decode method without any restrictions
    return jsonpickle.decode(data)

# Example usage with a malicious payload
malicious_payload = '{"py/object": "__main__.YourMaliciousClass"}'
result = vulnerable_deserialize(malicious_payload)