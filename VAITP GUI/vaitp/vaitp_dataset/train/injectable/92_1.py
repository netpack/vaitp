import xdg.Menu

# Sanitize the input before parsing
def sanitize_menu_file(menu_file):
    # Remove any malicious Category elements
    with open(menu_file, 'r') as f:
        menu_data = f.read()
    sanitized_menu_data = menu_data.replace('<Category>', '').replace('</Category>', '')
    return sanitized_menu_data

# Parse the sanitized .menu file
menu = xdg.Menu.parse(sanitize_menu_file('safe.menu'))