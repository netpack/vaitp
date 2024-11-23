import re

# Vulnerable regex pattern with overlapping capture groups
vulnerable_pattern = re.compile(r'^(?P<group1>a+)(?P<group2>a+)$')

def parse_user_agent(user_agent):
    # This function demonstrates the vulnerability
    match = vulnerable_pattern.match(user_agent)
    if match:
        return match.groupdict()
    return None

# Example usage demonstrating the potential for REDoS
user_agent_vulnerable = 'a' * 1000  # Maliciously crafted long string
result_vulnerable = parse_user_agent(user_agent_vulnerable)