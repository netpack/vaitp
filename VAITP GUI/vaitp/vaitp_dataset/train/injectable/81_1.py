from PIL import Image

def non_vulnerable_function(image_path):
    try:
        # Open the image file
        with Image.open(image_path) as image:
            
            # Get the number of bands in the image
            num_bands = len(image.getbands())
            
            # Add input validation to ensure num_bands is within a safe range
            if num_bands > 2**31 - 1:  # 2^31 - 1 is the maximum value for a 32-bit signed integer
                print("Error: Number of bands is too large.")
                return
            
            # Call the range function on the validated num_bands
            range(num_bands)
            
            # Process the image
            image.load()
            
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
non_vulnerable_function('example_image.jpg')