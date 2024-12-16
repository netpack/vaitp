def process_fli_data(data: bytes) -> None:
    # Vulnerable code (simulated):  No size check, leading to potential overflow.
    # buffer = bytearray(1024)  # Fixed size buffer.
    # buffer[:len(data)] = data  # Copies data into buffer without size check.

    # Fixed code: Check data size before copying.
    MAX_SIZE = 1024
    if len(data) > MAX_SIZE:
        raise ValueError("FLI data exceeds maximum allowed size.")
    buffer = bytearray(MAX_SIZE)
    buffer[:len(data)] = data

    # ... further processing of buffer ...
