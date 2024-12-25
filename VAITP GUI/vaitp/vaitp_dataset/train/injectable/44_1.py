from PIL import Image # Pillow < 8.1.1
import io
import os

def process_pdf(file_path):
    try:
        with open(file_path, 'rb') as f:
            # Read the PDF file into a bytes buffer
            pdf_bytes = f.read()
            
            # Create a BytesIO object from the bytes buffer
            buffer = io.BytesIO(pdf_bytes)
            
            # Open the PDF file using Pillow's Image.open method,
            # but with the `formats` parameter set to ['PDF']
            try:
               img = Image.open(buffer, formats=['PDF'])
               # Perform some operations on the image
               img.load()
               #Process page per page
               if hasattr(img, 'n_frames'):
                  for i in range(img.n_frames):
                     img.seek(i)
                     #perform the actual work, example:
                     #img.save(f"page{i}.png")
               else:
                  #If the PDF has only one image or Pillow could not recognize the pdf format
                  #perform work on the first page
                  #img.save(f"page0.png")
               
            except Exception as e:
               print(f"Error while processing the pdf {file_path}. Error: {e}")
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    

# Example usage:
if os.path.exists('malicious_pdf_file.pdf'):
    process_pdf('malicious_pdf_file.pdf')
else:
   print('malicious_pdf_file.pdf does not exists')