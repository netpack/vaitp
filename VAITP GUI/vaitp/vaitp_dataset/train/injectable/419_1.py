
import re

def execute_query(query):
    # Validate the query to allow only safe patterns
    if re.match(r'^[a-zA-Z0-9_ ]*$', query):  # Only allows alphanumeric and underscores
        return eval(query)  # Use eval() instead of exec() to prevent arbitrary code execution
    else:
        raise ValueError("Invalid query")