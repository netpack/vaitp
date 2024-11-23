class RDMAOperation:
    def __init__(self, lkey):
        self.lkey = lkey

    def perform_atomic_operation(self):
        # Simulate checking the validity of the lkey
        if not self.is_valid_lkey(self.lkey):
            raise ValueError("Invalid lkey supplied. Operation cannot proceed.")
        
        # Proceed with the atomic operation
        self.atomic_write()

    def is_valid_lkey(self, lkey):
        # In a real scenario, this would check against valid lkeys
        valid_lkeys = [1001, 1002, 1003]  # Example valid lkeys
        return lkey in valid_lkeys

    def atomic_write(self):
        # Simulate an atomic write operation
        print("Atomic write operation successful.")

# Example usage
try:
    operation = RDMAOperation(lkey=9999)  # Invalid lkey
    operation.perform_atomic_operation()
except ValueError as e:
    print(e)