def safe_select_where(query):
    # Example of a safe implementation that does not use eval
    # Parse the query to ensure it does not contain arbitrary code
    if "eval" in query or "exec" in query:
        raise ValueError("Unsafe query detected.")
    
    # Continue processing the query safely
    # For demonstration, we will just print the query
    print("Executing safe query:", query)

# Example of a crafted query
user_input = "SELECT * FROM table WHERE condition"
safe_select_where(user_input)