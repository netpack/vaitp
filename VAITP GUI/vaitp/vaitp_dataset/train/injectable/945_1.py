import signal
import time

# Define a handler for the SIGALRM signal to prevent long-running operations
def signal_handler(signum, frame):
    raise TimeoutError("Operation timed out")

# Set the signal handler and a timeout
signal.signal(signal.SIGALRM, signal_handler)

def safe_operation():
    # Set an alarm for 5 seconds
    signal.alarm(5)
    try:
        # Simulate a potentially long-running operation
        while True:
            time.sleep(1)  # Replace with actual logic
    except TimeoutError:
        print("Operation was terminated due to timeout.")
    finally:
        # Disable the alarm
        signal.alarm(0)

# Call the safe operation
safe_operation()