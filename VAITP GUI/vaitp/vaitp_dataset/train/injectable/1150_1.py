import sqlite3

def safe_insert(query, params=()):
    conn = sqlite3.connect('mydatabase.db')
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        conn.commit()
    except sqlite3.Error as e:
        raise ValueError(f"Invalid query detected: {e}")
    finally:
        conn.close()

# Example usage
try:
    safe_insert("INSERT INTO site_columns (name) VALUES (?)", ('new_column',))
    safe_insert("INSERT INTO site_columns (name) VALUES (?)", ('malicious_code',))
except ValueError as e:
    print(e)