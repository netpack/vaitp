def process_push_rule(push_rule):
    # Directly using the event_match pattern without validation
    if 'event_match' in push_rule:
        pattern = push_rule['event_match']
        # This could lead to performance issues with complex patterns
        match_events(pattern)

def match_events(pattern):
    # Simulate matching events against the pattern
    # This function could be exploited with complex wildcards
    events = get_events()  # Assume this retrieves a list of events
    for event in events:
        if matches_pattern(event, pattern):
            # Process matched event
            handle_matched_event(event)

def matches_pattern(event, pattern):
    # A naive matching implementation that could be slow with complex patterns
    return pattern in event['content']

# Example usage
push_rule = {
    'event_match': 'some*complex?pattern'
}
process_push_rule(push_rule)