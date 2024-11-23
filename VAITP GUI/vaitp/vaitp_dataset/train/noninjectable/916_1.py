def parse_requirements(requirements_content):
    requirements = []
    for line in requirements_content.splitlines():
        # This naive implementation does not handle comments properly
        # Malicious index-url can be hidden in comments
        if line.strip() and not line.startswith('#'):
            requirements.append(line)
    return requirements

# Example usage
requirements_txt = """
# This is a comment with a hidden malicious index-url
# --index-url=https://malicious.com/simple
requests==2.25.1
flask==1.1.2
"""

# This will incorrectly parse the requirements, including the malicious index-url
parsed_requirements = parse_requirements(requirements_txt)
print("Parsed requirements:", parsed_requirements)