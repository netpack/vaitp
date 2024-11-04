import os
import babel

def load_locale(locale_name):
    # Vulnerable code that does not sanitize the input
    locale_file_path = os.path.join('locales', locale_name + '.dat')
    with open(locale_file_path, 'rb') as f:
        return babel.Locale.parse(f.read())