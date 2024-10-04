# This code uses the Pillow library to open an image from a zip file
# The zip file does not contain any malicious header with a negative data size value
# The Pillow library sanitizes the input and checks for integer overflow
# This prevents the heap overflow attack described in CVE-2016-3076

from PIL import Image
zip_file = "safe.zip" # The zip file with a valid data size value
image = Image.open(zip_file) # This does not trigger the heap overflow