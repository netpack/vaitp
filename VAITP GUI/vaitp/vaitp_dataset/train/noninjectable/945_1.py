import time

def vulnerable_operation():
    # Simulate a long-running operation without any timeout or interruption
    while True:
        time.sleep(1)  # Replace with actual logic that could hang indefinitely

# Call the vulnerable operation
vulnerable_operation()