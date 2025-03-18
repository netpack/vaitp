import json
import pickle
import base64
import logging

logging.basicConfig(level=logging.INFO)

# Assume this is the vulnerable deserialization function
# in framework/wazuh/core/cluster/common.py, similar to as_wazuh_object
def as_wazuh_object_vulnerable(data):
    """
    Vulnerable deserialization function.  DO NOT USE IN PRODUCTION.
    This function is only provided to demonstrate the CVE.
    """
    try:
        # This simulates the vulnerable deserialization where arbitrary code
        # can be injected via a specially crafted dictionary.
        return pickle.loads(base64.b64decode(data['__unhandled_exc__']))
    except KeyError:
        return data


def as_wazuh_object_fixed(data):
    """
    Safe deserialization function.  This function avoids the vulnerability
    by explicitly checking and sanitizing the input data.
    """
    if isinstance(data, dict):
        # Check for potentially dangerous keys and reject them.
        if '__unhandled_exc__' in data:
            logging.error("Detected potentially malicious key '__unhandled_exc__' in data. Request rejected.")
            raise ValueError("Potentially malicious data detected.")

        # Recursively sanitize the dictionary (important for nested structures).
        for key, value in data.items():
            data[key] = as_wazuh_object_fixed(value)  # Recursive call
        return data
    elif isinstance(data, list):
        # Sanitize list elements as well
        return [as_wazuh_object_fixed(item) for item in data]
    else:
        # Primitive types are generally safe, but could add further checks if needed
        return data


# Example usage with a safe data structure
safe_data = {"message": "This is a safe message"}
fixed_data = as_wazuh_object_fixed(safe_data)
print(f"Fixed data (safe): {fixed_data}")

# Demonstration of how the vulnerable function can be exploited (DO NOT RUN IN PRODUCTION)
# Vulnerable Code (FOR DEMONSTRATION ONLY - DO NOT USE):
# import os
# class Exploit:
#     def __reduce__(self):
#         return (os.system, ('ls -la',))  # Example command - DO NOT USE MALICIOUS COMMANDS

# exploit = Exploit()
# serialized_exploit = base64.b64encode(pickle.dumps(exploit)).decode()
# vulnerable_data = {"__unhandled_exc__": serialized_exploit}

# try:
#     # This will execute the arbitrary code if as_wazuh_object_vulnerable is used
#     # DO NOT UNCOMMENT THIS LINE unless you understand the risks.
#     # vulnerable_result = as_wazuh_object_vulnerable(vulnerable_data)
#     # print(f"Vulnerable result: {vulnerable_result}") # Unreachable if exploit is successful
#     pass
# except Exception as e:
#     print(f"Vulnerable Code Executed (simulated): {e}")


# Demonstrating the fixed function rejecting the malicious data

try:
    # Attempt to process the malicious data with the fixed function
    vulnerable_data = {"__unhandled_exc__": "arbitrary_data"} # Simplified payload for demonstration
    fixed_result = as_wazuh_object_fixed(vulnerable_data)
    print(f"Fixed result (vulnerable data): {fixed_result}")  # This line should not be reached
except ValueError as e:
    print(f"Fixed function prevented exploitation: {e}")
except Exception as e:
    print(f"Unexpected error: {e}") # Handle any unexpected errors
