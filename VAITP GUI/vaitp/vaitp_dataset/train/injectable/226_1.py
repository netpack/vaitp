import re

def get_file_transfer_type(input_string):
    pattern = r"^(?:(?:https?|s?ftp):\/\/)?(?:[^\/\s]+(?::[^\/\s]+)?@)?(?:www\.)?([^:\/\s]+)(?::(\d+))?([^\/\s]*)?$"
    regex = re.compile(pattern)
    try:
        match = regex.match(input_string)
        if match:
            return match.groups()
        else:
            return None
    except re.error as e:
        # Handle the exception
        print(f"Error: {e}")
        return None