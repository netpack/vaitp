import sqlite3

id = request.GET.get("id", "")
if not id.isdigit():
    # Handle invalid input, e.g. return an error or default value.
    # For this example, we will return an empty result.
    username = None
else:
    connection = sqlite3.connect("your_database.db")  # Replace with your actual db connection logic
    cursor = connection.cursor()
    prepared_stmt = "SELECT username FROM auth_user WHERE id=?"
    cursor.execute(prepared_stmt, (id,))
    result = cursor.fetchone()
    username = result[0] if result else None
    connection.close()