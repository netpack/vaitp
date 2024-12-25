import re

def get_file_transfer_type(input_string):
    pattern = r"^(?:(?:https?|s?ftp):\/\/)?(?:[^\/\s]+(?::[^\/\s]+)?@)?(?:www\.)?([^:\/\s]+)(?::(\d+))?([^\/\s]*)?$"
    match = re.compile(pattern).match(input_string)
    if match:
        return match.groups()
    return None