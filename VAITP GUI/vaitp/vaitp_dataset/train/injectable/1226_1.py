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
        if self.tx_buf is not None:
            # Free the tx_buf after use
            self.free_buffer(self.tx_buf)
            self.tx_buf = None  # Ensure tx_buf is cleared after freeing

    def free_buffer(self, buffer):
        # Simulate freeing the buffer
        print(f"Buffer {buffer} freed.")

# Example usage
raydium = RaydiumI2C()
raydium.raydium_i2c_send("example data")
raydium.bank_switch()  # This will free the tx_buf