import sqlite3

# Hypothetical vulnerable function that uses user input directly in SQL query
def get_user_details(username):
    # Connect to an SQLite database (hypothetical database)
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    # Fetch and return results
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results