import pickle

class AMSNetwork:
    def __init__(self):
        self.data = None

    def receive_data(self, data):
        # Vulnerable code: unpickling data without validation
        self.data = pickle.loads(data)

    def process_data(self):
        # Process the data here
        print("Processing data:", self.data)

# Example usage
ams_net = AMSNetwork()
# An attacker could send malicious pickled data
malicious_data = b"... (malicious pickle data) ..."
ams_net.receive_data(malicious_data)
ams_net.process_data()