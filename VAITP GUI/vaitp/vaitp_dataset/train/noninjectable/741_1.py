from reportlab.pdfgen import canvas

def create_pdf(output_filename, img_url):
    c = canvas.Canvas(output_filename)
    c.drawString(100, 750, "Hello, ReportLab!")
    
    # Directly adding image without validation
    c.drawImage(img_url, 100, 600)
    
    c.save()

# Example usage with potentially untrusted URL
create_pdf("output.pdf", "http://127.0.0.1:5000/image.png")  # Vulnerable to SSRF