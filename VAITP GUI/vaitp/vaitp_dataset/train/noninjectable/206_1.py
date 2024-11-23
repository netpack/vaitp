import imageop

def vulnerable_image_processing(image_data):
    # Potentially unsafe processing of image data
    processed_image = imageop.some_image_operation(image_data)
    return processed_image

# Example of crafted image data that could exploit the vulnerability
crafted_image_data = b'\x00' * (2**32)  # Simulating a large image input
vulnerable_image_processing(crafted_image_data)