from PIL import Image, ImagePath
import io

def non_vulnerable_function(image_data):
    # Create an ImagePath object from the provided image data
    try:
        img = Image.open(io.BytesIO(image_data))
        path = ImagePath.Path(img.getbbox())
    except Exception:
        return None

    # Initialize the path object properly
    path._path = []

    # Call the getbbox function
    bbox = path.getbbox()

    # Return the resulting bounding box
    return bbox

# Example usage:
image_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\xfc\xff\x7f\x03\x00\x01\x01\xf9\xe2\x99\xd4\x00\x00\x00\x00IEND\xaeB`\x82"  # Replace with actual image data
result = non_vulnerable_function(image_data)
print(result)