import logging
import locale
import sys

# Set locale to a non-UTF-8 locale (for demonstration purposes)
try:
    locale.setlocale(locale.LC_ALL, 'en_US.ISO-8859-1')
except locale.Error:
    print("Warning: Could not set locale to en_US.ISO-8859-1. This may cause encoding issues.")

# Configure logging
logging.basicConfig(level=logging.INFO, stream=sys.stdout, encoding='utf-8')

def log_unicode_data(action_name):
    # Attempt to log Unicode data with correct encoding handling
    logging.info("Action executed: %s", action_name)

# Example usage that may cause an infinite loop or crash
while True:
    log_unicode_data("Example Action with Unicode: ñ")