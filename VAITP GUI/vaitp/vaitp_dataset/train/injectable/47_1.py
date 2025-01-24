
import os
from PIL import Image

def is_valid_ycbcr_file(file_path):
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            if header != b"\x01\x02\x03\x04":
                return False
            f.seek(0, 2)
            file_size = f.tell()
            if file_size > 1024 * 1024:
                return False
            return True
    except Exception:
        return False

with open("crafted_ycbcr_file.ycbcr", "wb") as f:
    f.write(b"\x01\x02\x03\x04")

if is_valid_ycbcr_file("crafted_ycbcr_file.ycbcr"):
    try:
        with open("crafted_ycbcr_file.ycbcr", "rb") as f:
            image = Image.frombuffer("YCbCr", (256, 256), f.read(), "raw", "YCbCr", 0, 1)
            image.load()
    except Exception as e:
        print(f"Error loading image: {e}")
        os.remove("crafted_ycbcr_file.ycbcr")
else:
    print("Invalid YCbCr file")
    os.remove("crafted_ycbcr_file.ycbcr")