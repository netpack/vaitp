import json

class AMSNetwork:
    def __init__(self):
        self.data = None

    def receive_data(self, data):
        # Secured code: using JSON for deserialization
        try:
            self.data = json.loads(data)
        except json.JSONDecodeError as e:
            print("Failed to decode JSON:", e)

    def process_data(self):
        # Process the data here
        print("Processing data:", self.data)

# Example usage
ams_net = AMSNetwork()
# Now, the data must be valid JSON
valid_data = '{"key": "value"}'  # Example of valid JSON data
ams_net.receive_data(valid_data)
ams_net.process_data()

# If an attacker tries to send malicious data, it will fail to decode
malicious_data = b"... (malicious data) ..."
ams_net.receive_data(malicious_data)
ams_net.process_data()