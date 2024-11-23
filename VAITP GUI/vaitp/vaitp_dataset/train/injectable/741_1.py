from reportlab.lib import utils
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import urllib.parse

# Define trusted schemes and hosts
trusted_schemes = {'http', 'https'}
trusted_hosts = {'example.com', 'localhost'}

def is_trusted_url(url):
    parsed_url = urllib.parse.urlparse(url)
    return (parsed_url.scheme in trusted_schemes and
            parsed_url.hostname in trusted_hosts)

def safe_add_image(c, img_url, x, y):
    if is_trusted_url(img_url):
        img = utils.ImageReader(img_url)
        c.drawImage(img, x, y)
    else:
        print(f"Blocked untrusted URL: {img_url}")

def create_pdf(output_filename, img_url):
    c = canvas.Canvas(output_filename, pagesize=letter)
    c.drawString(100, 750, "Hello, ReportLab!")
    
    # Use safe_add_image to add image if it's trusted
    safe_add_image(c, img_url, 100, 600)
    
    c.save()

# Example usage
create_pdf("output.pdf", "http://localhost/image.png")  # Change this to a trusted URL