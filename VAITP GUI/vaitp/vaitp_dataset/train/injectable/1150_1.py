def safe_insert(query):
    # Validate and sanitize the query to prevent arbitrary code execution
    if "INSERT" in query and not contains_dangerous_code(query):
        # Proceed with the insertion
        execute_query(query)
    else:
        raise ValueError("Invalid query detected!")

def contains_dangerous_code(query):
    # Basic check for potentially dangerous patterns
    dangerous_patterns = ["eval(", "exec(", "__import__(", "os.", "sys."]
    return any(pattern in query for pattern in dangerous_patterns)

def execute_query(query):
    # Function to execute the sanitized query against the database
    print(f"Executing query: {query}")

# Example usage
try:
    safe_insert("INSERT INTO site_columns (name) VALUES ('new_column')")
    safe_insert("INSERT INTO site_columns (name) VALUES ('malicious_code'); exec('os.system(\"ls\")')")
except ValueError as e:
    print(e)