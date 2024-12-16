def vulnerable_function(data):
    buffer = [0] * 10  # Small fixed-size buffer
    for i, byte in enumerate(data):
        buffer[i] = byte  # No bounds checking!
    # ... further processing ...
    return buffer

# Example of overflowing the buffer
malicious_data = [1] * 15  
result = vulnerable_function(malicious_data) 
print(result) # This will likely cause an error or unexpected behavior.