from PIL import Image

def process_image(data):
    try:
        img = Image.frombytes('RGB', (100, 100), data)
        # do something with the image
        return img
    except IOError as e:
        # catch and handle the exception raised by Pillow
        print(f"Error: {e}")
        return None

# create a highly compressed GIF data (exploit)
exploit_data = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF' * 1000000

result = process_image(exploit_data)
if result is None:
    print("Image processing failed")
else:
    print("Image processed successfully")