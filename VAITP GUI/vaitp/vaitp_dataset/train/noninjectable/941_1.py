from PIL import Image, ImageDraw, ImageFont

# Vulnerable code example
def vulnerable_draw_text(image, text, position, font):
    draw = ImageDraw.Draw(image)
    draw.text(position, text, font=font)

# Example usage
image = Image.new('RGB', (200, 100), color='white')
font = ImageFont.load_default()

# This long text could cause excessive memory allocation
vulnerable_draw_text(image, "A" * 10000, (10, 10), font)