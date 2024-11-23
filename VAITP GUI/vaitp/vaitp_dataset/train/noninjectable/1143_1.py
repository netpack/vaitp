from piccolo.engine import Engine
from piccolo.table import Table
from piccolo.columns import Varchar, File

class MediaFile(Table):
    title = Varchar()
    file = File()

# Allowing SVG files to be uploaded without restriction
def upload_file(file):
    # No validation on file type, allowing SVG uploads
    save_file(file)  # Function to save the uploaded file

# Example usage
upload_file(uploaded_svg_file)  # uploaded_svg_file is an SVG file being uploaded