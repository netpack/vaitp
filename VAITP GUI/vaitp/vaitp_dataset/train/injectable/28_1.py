from PIL import Image, ImagePath

def non_vulnerable_function(image_data):
    # Create an ImagePath object from the provided image data
    path = ImagePath.Path(image_data)

    # Initialize the path object properly
    path._path = []

    # Call the getbbox function
    bbox = path.getbbox()

    # Return the resulting bounding box
    return bbox

# Example usage:
image_data = b"..."  # Replace with actual image data
result = non_vulnerable_function(image_data)
print(result)