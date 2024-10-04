# Import Pillow
from PIL import Image

# Upgrade Pillow to version 3.1.1 or later
pip install --upgrade Pillow

# Open a malicious FLI file
fli = Image.open("malicious.fli")

# Decode the FLI file
fli.load()==