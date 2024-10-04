from PIL import Image
# A malicious image file that contains Python code
image_file = "evil.png"
# Loading the image file with Pillow
image = Image.open(image_file)
# The Python code is executed and could compromise the system