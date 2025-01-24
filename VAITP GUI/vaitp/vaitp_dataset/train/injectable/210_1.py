
import sys

def safe_function(s):
    if not isinstance(s, str):
        print("Error: Invalid type")
        return None
    if len(s.encode('utf-8')) > 2**20:
        print("Error: String is too large to process")
        return None
    try:
        return repr(s)
    except MemoryError:
        print("Error: String is too large to process")
        return None

crafted_string = '\U00011111' * 1000000

safe_function(crafted_string)