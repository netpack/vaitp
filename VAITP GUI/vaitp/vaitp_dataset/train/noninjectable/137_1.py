# This code uses the Pillow library to open an image from a zip file
# The zip file contains a malicious header with a negative data size value
# This causes the Pillow library to allocate a huge buffer and overflow it
# This can result in memory corruption or code execution

from PIL import Image
zip_file = "malicious.zip" # The zip file with the negative data size value
image = Image.open(zip_file) # This triggers the heap overflow