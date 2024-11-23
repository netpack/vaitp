import jsonpickle

# Safe deserialization function
def safe_deserialize(data):
    # Use jsonpickle's `decode` method with a whitelist of allowed classes
    return jsonpickle.decode(data, classes=(YourAllowedClass1, YourAllowedClass2))

# Example usage
malicious_payload = '{"py/object": "__main__.YourMaliciousClass"}'
try:
    result = safe_deserialize(malicious_payload)
except Exception as e:
    print("Deserialization failed:", e)