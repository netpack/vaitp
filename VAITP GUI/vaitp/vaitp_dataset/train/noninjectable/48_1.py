from PIL import Image # Pillow < 8.2.0

def vulnerable_function(image_data):
    # Create an image object from the image data
    img = Image.frombytes('L', (100, 100), image_data)

    # Perform some operation on the image
    img.show()

# Create some malicious image data that triggers the vulnerability
malicious_image_data = b'\x00' * 10000  # Create a large buffer of zeros

# Call the vulnerable function with the malicious image data
vulnerable_function(malicious_image_data)