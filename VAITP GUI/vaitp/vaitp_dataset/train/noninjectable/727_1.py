import logging
import locale

# Set locale to a non-UTF-8 locale (for demonstration purposes)
locale.setlocale(locale.LC_ALL, 'en_US.ISO-8859-1')

# Configure logging
logging.basicConfig(level=logging.INFO)

def log_unicode_data(action_name):
    # Attempt to log Unicode data without handling encoding
    logging.info("Action executed: %s", action_name)

# Example usage that may cause an infinite loop or crash
while True:
    log_unicode_data("Example Action with Unicode: ñ")