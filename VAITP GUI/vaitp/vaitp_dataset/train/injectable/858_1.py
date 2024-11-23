def validate_push_rule(push_rule):
    # Example of a basic check for event_match patterns
    if 'event_match' in push_rule:
        pattern = push_rule['event_match']
        # Limit the complexity of the pattern to prevent poor performance
        if is_complex_pattern(pattern):
            raise ValueError("Complex patterns are not allowed.")
    return True

def is_complex_pattern(pattern):
    # A simple check for wildcards or excessive complexity
    return '*' in pattern or '?' in pattern

# Example usage
try:
    push_rule = {
        'event_match': 'some*complex?pattern'
    }
    validate_push_rule(push_rule)
except ValueError as e:
    print(e)