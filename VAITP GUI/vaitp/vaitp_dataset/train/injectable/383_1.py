# Hypothetical example
class OutputFilter:
    def __init__(self):
        self.buffer = bytearray()

    def read(self, size):
        # Secure code: enforce a maximum read size
        if size > 16384:
            raise ValueError("Requested size exceeds maximum allowed limit of 16384 bytes")
        
        # Proceed to read the data safely
        data = self._read_from_source(size)
        self.buffer.extend(data)
        return data

    def _read_from_source(self, size):
        # Simulated data reading
        return b"Some data" * (size // 10)  # Simulate reading a large amount of data