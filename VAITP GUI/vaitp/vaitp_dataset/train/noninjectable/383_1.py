# Hypothetical example
class OutputFilter:
    def __init__(self):
        self.buffer = bytearray()

    def read(self, size):
        # Assume this method reads data from some source
        if size > 16384:
            # Vulnerable code: reading more than allowed without proper checks
            data = self._read_from_source(size)
            if len(data) > size:
                data = data[:size]
            self.buffer.extend(data)
            return data
        else:
            data = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return data

    def _read_from_source(self, size):
        # Simulated data reading that could lead to memory issues
        return b"Some data" * (size // 10)  # Simulate reading a large amount of data