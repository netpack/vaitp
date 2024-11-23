import time

def analytics_dashboard(user_hash, stored_hash):
    # Simulated time delay for demonstration purposes
    time.sleep(0.1)  # Simulate processing time
    if user_hash == stored_hash:  # Vulnerable comparison
        return "Access Granted"
    else:
        return "Access Denied"

# Example usage
stored_hash = b'secret_hash'
user_hash = b'user_provided_hash'
print(analytics_dashboard(user_hash, stored_hash))