class Device:
    def __init__(self):
        self.private_data = None

    def add_device(self):
        # Simulate device_add() success
        self.private_data = "allocated_resource"
        return True

    def remove_device(self):
        if self.private_data is not None:
            # Simulate proper resource release
            self.put_device()
        else:
            print("No device to remove.")

    def put_device(self):
        # Release resources
        print("Releasing resources.")
        self.private_data = None

# Simulate the process
device = Device()
if device.add_device():
    print("Device added successfully.")
    # Simulate an error path that would require cleanup
    device.remove_device()
else:
    print("Failed to add device.")