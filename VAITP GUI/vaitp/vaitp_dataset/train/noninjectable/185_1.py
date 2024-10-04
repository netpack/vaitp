import sqlite3

# Vulnerable function
def get_user_details_vulnerable(username):
    # Directly formatting user input into the query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()