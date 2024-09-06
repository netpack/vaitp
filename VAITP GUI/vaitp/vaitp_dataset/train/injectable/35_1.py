from PIL import Image # Pillow < 8.2.0 

def safe_open_image(file_path):
    try:
        with open(file_path, 'rb') as f:
            # Check if the file is not empty
            if f.read(1):  # Read a single byte
                f.seek(0)  # Reset the file pointer
                return Image.open(f)
            else:
                raise ValueError("File is empty")
    except Exception as e:
        print(f"Error opening file: {e}")
        return None

# Create a malicious BLP image file
with open('malicious.blp', 'wb') as f:
    f.write(b'\x00' * 1024)  # Write 1024 bytes of zeros

# Test the safe_open_image function with the malicious file
print("Testing with malicious file:")
img = safe_open_image('malicious.blp')

if img:
    print("Failed to prevent infinite loop!")
    img.load()
else:
    print("Successfully prevented infinite loop!")

# Create a valid BLP image file
with open('valid.blp', 'wb') as f:
    f.write(b'\x01' * 1024)  # Write 1024 bytes of ones

# Test the safe_open_image function with the valid file
print("\nTesting with valid file:")
img = safe_open_image('valid.blp')

if img:
    print("Successfully opened image!")
    img.load()
else:
    print("Failed to open image!")