import jsonpickle

# Safe deserialization function
def safe_deserialize(data):
    try:
        # Use jsonpickle's `decode` method with a whitelist of allowed classes
        return jsonpickle.decode(data, classes=(str, int, float, list, dict, tuple, bool, type(None)))
    except jsonpickle.json.JSONDecodeError:
         return None
    except Exception:
        return None

# Example usage
malicious_payload = '{"py/object": "__main__.YourMaliciousClass"}'
result = safe_deserialize(malicious_payload)
if result is None:
    print("Deserialization failed: Invalid JSON or disallowed object.")
else:
    print("Deserialized data:", result)