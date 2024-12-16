import os
import subprocess

def safe_image_processing(image_path):
    # Validate the image type before processing
    allowed_image_types = ['.qcow2', '.raw', '.img']
    if not any(image_path.endswith(ext) for ext in allowed_image_types):
        raise ValueError("Invalid image type. Allowed types are: " + ", ".join(allowed_image_types))

    # Set a safe working directory to prevent unauthorized access
    safe_working_dir = '/tmp/safe_image_processing'
    os.makedirs(safe_working_dir, exist_ok=True)

    # Use a subprocess to call qemu-img with a limited set of options
    try:
        result = subprocess.run(['qemu-img', 'info', image_path], cwd=safe_working_dir, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error processing image:", e.stderr)
        raise

# Example usage
# safe_image_processing('/path/to/image.qcow2')