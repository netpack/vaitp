import sqlite3

def safe_insert_query(db_connection, table_name, column_names, values):
    if not isinstance(column_names, list) or not isinstance(values, list):
        raise ValueError("Column names and values must be lists.")

    if not all(isinstance(col, str) for col in column_names):
        raise ValueError("Column names must be strings.")

    if len(column_names) != len(values):
        raise ValueError("Number of column names and values must match.")
    
    placeholders = ', '.join('?' for _ in values)
    columns_str = ', '.join(column_names)
    
    query = f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders})"
    db_connection.execute(query, values)


# Example usage
conn = sqlite3.connect('example.db')
try:
    safe_insert_query(conn, "users", ["name"], ["Alice"])
    safe_insert_query(conn, "users", ["name", "age"], ["Bob", 30])
finally:
    conn.close()
