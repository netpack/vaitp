try:
    import imageop
except ImportError:
    print("The 'imageop' module is not available. Please install it or use a different image processing library.")
    exit()


def vulnerable_image_processing(image_data):
    # Potentially unsafe processing of image data
    try:
        processed_image = imageop.some_image_operation(image_data)
    except Exception as e:
         print(f"Error during image processing: {e}")
         return None
    return processed_image

# Example of crafted image data that could exploit the vulnerability
crafted_image_data = b'\x00' * (2**20)  # Simulating a large image input (reduced size)
vulnerable_image_processing(crafted_image_data)