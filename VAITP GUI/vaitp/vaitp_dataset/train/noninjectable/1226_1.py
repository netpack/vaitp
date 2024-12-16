class RaydiumI2C:
    def __init__(self):
        self.tx_buf = None

    def raydium_i2c_send(self, data):
        # Simulate sending data over I2C
        self.tx_buf = self.allocate_buffer(data)

    def allocate_buffer(self, data):
        # Simulate buffer allocation
        return data

    def bank_switch(self):
        # Simulate BANK_SWITCH command
        # Vulnerability: tx_buf is not freed after use
        if self.tx_buf is not None:
            print(f"Buffer {self.tx_buf} used, but not freed.")
            # No freeing of tx_buf here, leading to a memory leak

# Example usage
raydium = RaydiumI2C()
raydium.raydium_i2c_send("example data")
raydium.bank_switch()  # This will not free the tx_buf, causing a memory leak