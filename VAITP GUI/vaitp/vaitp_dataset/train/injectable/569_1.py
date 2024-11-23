import hashlib

def verify_firmware_image(image_path, expected_hash):
    """Verify the integrity of the firmware image before processing it."""
    # Calculate the hash of the firmware image
    with open(image_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Compare the calculated hash with the expected hash
    if file_hash != expected_hash:
        raise ValueError("Firmware image verification failed! Potential tampering detected.")
    
    # Proceed with the firmware update if the hash is valid
    process_firmware_update(image_path)

def process_firmware_update(image_path):
    """Process the firmware update."""
    # Logic to apply the firmware update goes here
    print(f"Firmware image {image_path} is valid and is being processed for update.")

# Example usage
expected_firmware_hash = "expected_sha256_hash_here"
firmware_image_path = "path_to_firmware_image.img"

try:
    verify_firmware_image(firmware_image_path, expected_firmware_hash)
except ValueError as e:
    print(e)