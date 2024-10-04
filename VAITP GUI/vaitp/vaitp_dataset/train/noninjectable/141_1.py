# Import Pillow
from PIL import Image

# Open a malicious FLI file
fli = Image.open("malicious.fli")

# Decode the FLI file
fli.load()