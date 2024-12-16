# Simulate the vulnerable behavior of the osdp_reply_name function
def osdp_reply_name(reply_id):
    # Simulated names array with limited range
    names = [b"ACK", b"XRD"]  # Only two valid names
    # Attempt to access a name based on reply_id
    name = names[reply_id]  # This can lead to an out-of-bounds access
    if name[0] == b'\0':
        raise Exception("Null name will cause a crash")
    return name

# Example of triggering the vulnerability
try:
    print(osdp_reply_name(2))  # This reply_id is out of the defined range
except Exception as e:
    print(f"Caught exception: {e}")