class Device:
    def __init__(self):
        self.private_data = None

    def add_device(self):
        # Simulate device_add() success
        self.private_data = "allocated_resource"
        return True

    def remove_device(self):
        # Improper resource release; missing put_device() call
        if self.private_data is not None:
            print("Device removed, but resources not released.")
            self.private_data = None
        else:
            print("No device to remove.")

# Simulate the process
device = Device()
if device.add_device():
    print("Device added successfully.")
    # Simulate an error path that would require cleanup
    device.remove_device()
else:
    print("Failed to add device.")