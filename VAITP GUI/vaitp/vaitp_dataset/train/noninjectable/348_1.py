import re

def parse_schema(schema_definition):
    # Vulnerable regex pattern that can be exploited
    pattern = re.compile(r'(\w+)\s*=\s*(.*?);')
    
    # This could be a user-defined schema that is not sanitized
    for line in schema_definition.splitlines():
        match = pattern.match(line)
        if match:
            print(f"Parsed: {match.group(1)} = {match.group(2)}")