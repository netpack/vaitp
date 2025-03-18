import json
import base64
import pickle

class UnsafeObject:
    def __reduce__(self):
        import os
        return (os.system, ('touch /tmp/pwned',))  # Arbitrary command

def as_wazuh_object(dct):
    """
    This function attempts to convert a dictionary into a Wazuh object.
    In vulnerable versions, it does not properly sanitize the input,
    leading to potential deserialization vulnerabilities.
    """
    if '__unhandled_exc__' in dct:
        # Vulnerable code: Directly uses the dictionary as is without sanitization
        # This allows an attacker to inject malicious data.
        # return dct['__unhandled_exc__'] #DO NOT UNCOMMENT, IT'S THE VULNERABILITY
        pass #Fixed code would properly validate or reject the __unhandled_exc__

    return dct

def process_request(request_data):
    """
    Simulates the processing of a request.  The request data is assumed to
    be a JSON string that needs to be deserialized.
    """
    try:
        data = json.loads(request_data)
        processed_data = as_wazuh_object(data)
        return processed_data
    except Exception as e:
        return f"Error processing request: {e}"

# Example of a vulnerable request
# This crafted JSON payload exploits the unsafe deserialization in `as_wazuh_object`.
# The 'UnsafeObject' class, when deserialized, executes arbitrary code.
# It mimics the '__unhandled_exc__' behavior, triggering code execution when
# the vulnerable 'as_wazuh_object' function directly returns the unsanitized dictionary.
# NEVER RUN UNSAFE CODE!
#payload = json.dumps({'__unhandled_exc__': UnsafeObject()})

# Simulate the vulnerable server processing the malicious request.
#This will only execute if you uncomment the return statement in 'as_wazuh_object'

#result = process_request(payload)
#print(f"Processed Result: {result}")