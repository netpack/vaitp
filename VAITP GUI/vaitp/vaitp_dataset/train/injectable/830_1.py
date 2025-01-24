import re

# Fixed version with non-overlapping capture groups
fixed_pattern = re.compile(r'^(?P<group1>a+)(?P<group2>b+)$')

def safe_parse_user_agent(user_agent):
    match = fixed_pattern.match(user_agent)
    if match:
        return match.groupdict()
    return None