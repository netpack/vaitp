import re

def get_file_transfer_type(input_string):
    pattern = r"^(?:(?:https?|s?ftp):\/\/)?(?:[^\/\s]+(?::[^\/\s]+)?@)?(?:www\.)?([^:\/\s]+)(?::(\d+))?([^\/\s]*)?$"
    re.compile(pattern).match(input_string)