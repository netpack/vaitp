from PIL import Image

def getrgb(image_path):
    try:
        with Image.open(image_path) as img:
            img.load()
            return list(img.getdata())
    except Exception:
        return None