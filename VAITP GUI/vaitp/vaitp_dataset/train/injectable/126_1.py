from PIL import Image
# A malicious image file that contains Python code
image_file = "evil.png"
# Loading the image file with Pillow using a safe loader
image = Image.open(image_file, mode="r")
# The Python code is not executed and raises an exception