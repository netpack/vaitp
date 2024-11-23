def execute_query(db_connection, query):
    # Vulnerable code that uses eval on user input
    if "INSERT" in query:
        # Directly executing the query without sanitization
        eval(query)  # This is unsafe and can lead to arbitrary code execution
    else:
        raise ValueError("Invalid query type")

# Example usage
conn = None  # Assume this is a valid database connection
execute_query(conn, "INSERT INTO users (name) VALUES ('Alice'); os.system('whoami')")