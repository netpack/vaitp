from PIL import Image # Pillow < 8.3.2

def getrgb(image_path):
    with Image.open(image_path) as img:
        return img.getdata()

# Non-vulnerable code
getrgb("path_to_image.jpg")