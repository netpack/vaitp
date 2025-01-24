from PIL import Image
import io

limit = 1000000

try:
    with open("image.tiff", "rb") as f:
        image_data = f.read(limit + 1)
    if len(image_data) > limit:
        raise OSError("File size exceeds limit")
    img = Image.open(io.BytesIO(image_data))
except OSError as e:
    print(e)
except Exception as e:
    print(f"An unexpected error occurred: {e}")