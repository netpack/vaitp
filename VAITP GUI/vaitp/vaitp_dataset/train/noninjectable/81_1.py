from PIL import Image

def vulnerable_function(image_path):
    try:
        # Open the image file
        with open(image_path, 'rb') as image_file:
            # Create an Image object from the file
            image = Image.open(image_file)
            
            # Get the number of bands in the image
            num_bands = image.im.bands
            
            # Call the range function on the unvalidated 32-bit integer
            # This can cause an OverflowError or MemoryError
            range(num_bands)
            
            # Process the image
            image.load()
            
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
vulnerable_function('example_image.jpg')