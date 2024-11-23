def process_firmware_update(image_path):
    """Process the firmware update without verifying the image."""
    # Arbitrary code execution risk: directly executing the firmware image
    with open(image_path, 'rb') as f:
        firmware_code = f.read()
    
    # Execute the firmware code directly (vulnerable to arbitrary code execution)
    exec(firmware_code)

# Example usage
firmware_image_path = "path_to_firmware_image.img"
process_firmware_update(firmware_image_path)