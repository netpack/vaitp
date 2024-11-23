import mysql.connector

# Establish a connection to the MySQL database without secure options
connection = mysql.connector.connect(
    host='localhost',
    user='your_username',
    password='your_password',
    database='your_database'
)

# Example of executing a potentially unsafe query
try:
    cursor = connection.cursor()
    # Vulnerable to SQL injection if user input is not sanitized
    user_input = "some_value'; DROP TABLE your_table; --"
    cursor.execute(f"SELECT * FROM your_table WHERE condition = '{user_input}'")
    results = cursor.fetchall()
    for row in results:
        print(row)
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    cursor.close()
    connection.close()