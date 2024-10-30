import re

# Patched regex pattern that mitigates ReDoS
pattern = r"SELECT\s+(?P<columns>[\w\s,]+)\s+FROM\s+(?P<table>\w+)(?:\s+WHERE\s+(?P<condition>[^;]+))?"

def parse_sql(query):
    match = re.match(pattern, query)
    if match:
        return match.groupdict()
    return None

# Example of a safe input
query = "SELECT a, b, c FROM my_table WHERE a = 'value' AND b = 'another_value'"
result = parse_sql(query)
print(result)