class TlsLite:
    def __init__(self):
        self.buffer = bytearray(10)  # Fixed-size buffer

    def receive_data(self, data):
        # Vulnerable: No check on the length of the incoming data
        for i in range(len(data)):
            self.buffer[i] = data[i]  # Potential buffer overflow if data is too large

    def process_data(self):
        # Simulate processing the buffer
        print("Processing data:", self.buffer)

# Example usage
tls_lite = TlsLite()

# Simulating an attacker sending a large amount of data
malicious_data = bytearray(100)  # 100 bytes, larger than the buffer
try:
    tls_lite.receive_data(malicious_data)  # This will cause an issue
    tls_lite.process_data()
except IndexError as e:
    print("Caught an exception:", e)