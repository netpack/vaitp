import re

def safe_strip_tags(value):
    # Limit the number of iterations to prevent infinite loops
    max_iterations = 1000
    iterations = 0
    
    while iterations < max_iterations:
        # Use a regex to remove HTML tags
        new_value = re.sub(r'<[^>]+>', '', value)
        if new_value == value:
            break
        value = new_value
        iterations += 1
    
    return value