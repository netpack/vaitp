from PIL import Image

def vulnerable_crop(image, box):
    # Directly using the box values without validation
    left, upper, right, lower = box
    return image.crop(box)

# Example usage
if __name__ == "__main__":
    img = Image.open("example.jpg")
    crop_box = (0, 0, 1000000000, 1000000000)  # Example of a potentially dangerous large crop box
    cropped_image = vulnerable_crop(img, crop_box)
    cropped_image.show()