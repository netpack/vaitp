from PIL import Image, ImagePath

def vulnerable_function(image_data):
    # Create an ImagePath object from the provided image data
    path = ImagePath.Path(image_data)

    # Call the vulnerable path_getbbox function
    bbox = path.getbbox()

    # Return the resulting bounding box
    return bbox

# Example usage:
image_data = b"..."  # Replace with actual image data
result = vulnerable_function(image_data)
print(result)