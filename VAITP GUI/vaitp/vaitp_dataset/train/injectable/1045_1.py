import hmac
import time

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
    if constant_time_compare(user_hash, stored_hash):
        return "Access Granted"
    else:
        return "Access Denied"

# Example usage
stored_hash = b'secret_hash'
user_hash = b'user_provided_hash'
print(analytics_dashboard(user_hash, stored_hash))