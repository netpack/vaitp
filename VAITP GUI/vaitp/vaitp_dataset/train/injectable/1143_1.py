from piccolo.engine import Engine
from piccolo.table import Table
from piccolo.columns import Varchar, Boolean, File

class MediaFile(Table):
    title = Varchar()
    is_svg_allowed = Boolean(default=False)

# Ensure that SVG files are not allowed for upload
def upload_file(file):
    if file.filename.endswith('.svg'):
        raise ValueError("SVG files are not allowed for upload.")
    # Proceed with the upload process for other file types

# Example usage
try:
    upload_file(uploaded_file)  # uploaded_file is the file being uploaded
except ValueError as e:
    print(e)