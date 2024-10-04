import sqlite3

# Patched function
def get_user_details_patched(username):
    # Using a parameterized query to safely incorporate user input
    query = "SELECT * FROM users WHERE username = ?"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query, (username,))
    return cursor.fetchall()