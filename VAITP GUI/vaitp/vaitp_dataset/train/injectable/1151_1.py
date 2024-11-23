def safe_insert(query):
    # Validate and sanitize the query to prevent arbitrary code execution
    if "eval(" in query or "exec(" in query:
        raise ValueError("Unsafe query detected!")
    # Proceed with the safe execution of the insert query
    # Database execution logic here (e.g., using parameterized queries)
    print("Executing safe insert query:", query)

# Example of a safe insert
safe_insert("INSERT INTO list_items (name) VALUES ('item1')")