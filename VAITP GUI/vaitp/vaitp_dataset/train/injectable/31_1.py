from PIL import Image # Assumes a non patched version of Pillow < 8.3.2


def convert_image(image_path):

    image = Image.open(image_path)

    try:

        # Validate the image file to prevent buffer overflow

        if image.width > 10000 or image.height > 10000:

            raise ValueError("Invalid image dimensions")

        image.convert('RGB')  # Still vulnerable, but with input validation this code can never be executed

    except ValueError as e:

        print(f"Error: {e}")

        return None

    return image


# Example usage:

image_path = 'path/to/image.jpg'

converted_image = convert_image(image_path)