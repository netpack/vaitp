import sqlite3

def safe_insert_query(db_connection, query):
    # Avoid using eval or exec on user input
    if "INSERT" in query:
        # Perform input validation or sanitization here
        # Example: only allow certain formats or values
        sanitized_query = query.replace(";", "").replace("--", "")  # Simple sanitization
        db_connection.execute(sanitized_query)
    else:
        raise ValueError("Invalid query type")

# Example usage
conn = sqlite3.connect('example.db')
try:
    safe_insert_query(conn, "INSERT INTO users (name) VALUES ('Alice')")
finally:
    conn.close()