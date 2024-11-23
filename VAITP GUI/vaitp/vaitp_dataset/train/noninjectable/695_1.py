import re

def vulnerable_strip_tags(value):
    while True:
        new_value = re.sub(r'<[^>]+>', '', value)
        if new_value == value:
            break
        value = new_value
    
    return value