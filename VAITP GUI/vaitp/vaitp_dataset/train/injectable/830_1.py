import re

# Example of a regex pattern that could be vulnerable to REDoS due to overlapping capture groups
# This is a simplified representation and not the actual implementation from uap-core
vulnerable_pattern = re.compile(r'^(?P<group1>a+)(?P<group2>a+)$')

def parse_user_agent(user_agent):
    # This function demonstrates the vulnerability
    match = vulnerable_pattern.match(user_agent)
    if match:
        return match.groupdict()
    return None

# Fixed version with non-overlapping capture groups
fixed_pattern = re.compile(r'^(?P<group1>a+)(?P<group2>b+)$')

def safe_parse_user_agent(user_agent):
    match = fixed_pattern.match(user_agent)
    if match:
        return match.groupdict()
    return None

# Example usage
user_agent_vulnerable = 'aaaaaa'
user_agent_fixed = 'aaaabbbb'

# Demonstrating the vulnerable function (may cause performance issues)
# result_vulnerable = parse_user_agent(user_agent_vulnerable)

# Safe function call
result_fixed = safe_parse_user_agent(user_agent_fixed)