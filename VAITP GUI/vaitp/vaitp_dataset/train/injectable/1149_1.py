def safe_insert_query(query):
    # Validate the query to ensure it does not contain unsafe code
    if "eval" in query or "exec" in query:
        raise ValueError("Unsafe query detected!")
    # Proceed with the safe execution of the query
    execute_query(query)

def execute_query(query):
    # Logic to execute the query safely
    print("Executing query:", query)

# Example of a safe insert query
safe_insert_query("INSERT INTO my_table (column) VALUES ('safe_value')")