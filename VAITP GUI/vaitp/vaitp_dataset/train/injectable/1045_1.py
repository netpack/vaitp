import hmac
import time
import os

def constant_time_compare(val1, val2):
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0

def analytics_dashboard(user_hash, stored_hash):
    # Simulated time delay for demonstration purposes
    time.sleep(0.1)  # Simulate processing time
    if hmac.compare_digest(user_hash, stored_hash):
        return "Access Granted"
    else:
        return "Access Denied"

# Example usage
stored_hash = hmac.new(os.urandom(32), b'secret_hash', digestmod="sha256").digest()
user_hash = hmac.new(os.urandom(32), b'user_provided_hash', digestmod="sha256").digest()
print(analytics_dashboard(user_hash, stored_hash))