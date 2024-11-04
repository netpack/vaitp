import os
import babel

def load_locale(locale_name):
    # Sanitize the input to prevent directory traversal
    if not locale_name.isalnum():  # Only allow alphanumeric characters
        raise ValueError("Invalid locale name")
    
    locale_file_path = os.path.join('locales', locale_name + '.dat')
    
    # Ensure the file path is within the expected directory
    if not os.path.abspath(locale_file_path).startswith(os.path.abspath('locales')):
        raise ValueError("Attempted directory traversal detected")
    
    with open(locale_file_path, 'rb') as f:
        return babel.Locale.parse(f.read())