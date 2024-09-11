from PIL import Image # Pillow < 8.1.1

def is_valid_ycbcr_file(file_path):
    with open(file_path, "rb") as f:
        # Check the file header to ensure it's a valid YCbCr file
        header = f.read(4)
        if header != b"\x01\x02\x03\x04":  # Replace with the correct header for YCbCr files
            return False

        # Check the file size to prevent buffer overflow
        file_size = f.seek(0, 2)
        if file_size > 1024 * 1024:  # Adjust the maximum file size as needed
            return False

    return True

# Create a crafted YCbCr file
with open("crafted_ycbcr_file.ycbcr", "wb") as f:
    f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15")  # crafted YCbCr data

# Check the file before loading it
if is_valid_ycbcr_file("crafted_ycbcr_file.ycbcr"):
    image = Image.open("crafted_ycbcr_file.ycbcr")
    image.load()
else:
    print("Invalid YCbCr file")