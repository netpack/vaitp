def load_image(image_data):
    # Assume these functions extract width and height from image data
    width = get_image_width(image_data)  # Function to get image width
    height = get_image_height(image_data)  # Function to get image height

    # Potentially unsafe calculation leading to integer overflow
    image_buffer_size = width * height * 3  # Assuming RGB image

    # Directly allocating buffer without any checks
    image_buffer = bytearray(image_buffer_size)

    # ... (code to fill the buffer with image data) ...

    return image_buffer