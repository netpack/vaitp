import sqlite3

# Patched function with parameterized query to prevent SQL injection
def get_user_details(username):
    # Connect to an SQLite database (hypothetical database)
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()
    
    # Secure SQL query using parameterization
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    # Fetch and return results
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results