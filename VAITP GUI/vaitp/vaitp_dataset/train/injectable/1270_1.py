import threading
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class BluetoothDevice:
    def __init__(self, max_measurement_requests=5, request_window=10):
        self.is_connected = False
        self.measurement_count = 0
        self.last_request_time = 0
        self.lock = threading.Lock()
        self.max_measurement_requests = max_measurement_requests
        self.request_window = request_window  # Time window in seconds
        self.blocked_until = 0 # Time until device is blocked due to excessive requests

    def connect(self):
        """Simulates connecting to the device."""
        logging.info("Connecting to the Bluetooth device...")
        time.sleep(1)  # Simulate connection time
        self.is_connected = True
        logging.info("Device connected.")

    def disconnect(self):
        """Simulates disconnecting from the device."""
        logging.info("Disconnecting from the Bluetooth device...")
        self.is_connected = False
        logging.info("Device disconnected.")

    def start_measurement(self):
        """Simulates starting a measurement, with rate limiting."""
        with self.lock:  # Ensure thread-safe access to shared resources
            current_time = time.time()

            # Check if device is blocked
            if current_time < self.blocked_until:
                logging.warning(f"Device blocked until {self.blocked_until}. Measurement request rejected.")
                return False

            #Implement rate limiting logic
            if current_time - self.last_request_time < self.request_window:
                self.measurement_count += 1
                if self.measurement_count > self.max_measurement_requests:
                    #Block the device temporarily
                    block_duration = 60 # Block for 60 seconds
                    self.blocked_until = current_time + block_duration
                    logging.error(f"Rate limit exceeded. Device blocked for {block_duration} seconds.")
                    self.measurement_count = 0 # Reset count after blocking
                    self.last_request_time = current_time # Reset time
                    return False

            else:
                # Reset measurement count after request_window seconds of inactivity
                self.measurement_count = 1
                self.last_request_time = current_time

            logging.info("Starting measurement...")
            time.sleep(0.5)  # Simulate measurement time
            logging.info("Measurement complete.")
            return True