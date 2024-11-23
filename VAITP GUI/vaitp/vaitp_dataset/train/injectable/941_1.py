from PIL import Image, ImageDraw, ImageFont

def safe_draw_text(image, text, position, font, max_length=100):
    # Limit the length of the text to prevent excessive memory allocation
    if len(text) > max_length:
        raise ValueError("Text length exceeds maximum allowed length.")
    
    draw = ImageDraw.Draw(image)
    draw.text(position, text, font=font)

# Example usage
image = Image.new('RGB', (200, 100), color='white')
font = ImageFont.load_default()

try:
    safe_draw_text(image, "This is a safe text", (10, 10), font)
    # Uncomment the line below to see the exception being raised
    # safe_draw_text(image, "A" * 1000, (10, 10), font)  # This would raise an error
except ValueError as e:
    print(e)