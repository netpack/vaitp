import subprocess

def vulnerable_image_processing(image_path):
    # This function does not validate the image type before processing
    # which could lead to exploitation with crafted images.

    # Directly using qemu-img without restrictions
    result = subprocess.run(['qemu-img', 'info', image_path], check=True, capture_output=True, text=True)
    return result.stdout

# Example usage
# vulnerable_image_processing('/path/to/crafted/image.img')