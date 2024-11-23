import logging
import locale

# Ensure the locale is set to UTF-8
try:
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except locale.Error:
    # Fallback to a safe locale if UTF-8 is not available
    locale.setlocale(locale.LC_ALL, 'C.UTF-8')

# Configure logging
logging.basicConfig(level=logging.INFO)

def log_unicode_data(action_name):
    # Safely encode the action name to avoid issues with non-UTF-8 locales
    try:
        logging.info("Action executed: %s", action_name)
    except UnicodeEncodeError:
        logging.error("Failed to log action name due to encoding issues.")

# Example usage
log_unicode_data("Example Action with Unicode: ñ")