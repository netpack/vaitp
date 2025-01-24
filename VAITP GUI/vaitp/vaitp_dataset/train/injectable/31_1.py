from PIL import Image
import io

def convert_image(image_path):
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()
        image = Image.open(io.BytesIO(image_data))


        # Validate the image file to prevent buffer overflow
        if image.width > 10000 or image.height > 10000:
            raise ValueError("Invalid image dimensions")


        image = image.convert('RGB')

    except (ValueError, OSError, IOError) as e:
        print(f"Error: {e}")
        return None

    return image


# Example usage:
image_path = 'path/to/image.jpg'
converted_image = convert_image(image_path)