import xdg.Menu
import tempfile

# Sanitize the input before parsing
def sanitize_menu_file(menu_file):
    # Remove any malicious Category elements
    with open(menu_file, 'r') as f:
        menu_data = f.read()
    sanitized_menu_data = menu_data.replace('<Category>', '').replace('</Category>', '')
    
    # Create a temporary file to store the sanitized data
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        tmp_file.write(sanitized_menu_data)
        tmp_file_path = tmp_file.name
    
    return tmp_file_path

# Parse the sanitized .menu file
menu = xdg.Menu.parse(sanitize_menu_file('safe.menu'))