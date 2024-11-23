import mysql.connector

# Example of connecting to a MySQL database using a vulnerable version of Connector/Python
# This code does not include proper error handling or authentication checks
connection = mysql.connector.connect(
    host='localhost',
    user='',
    password='',
    database='your_database'
)

# Potentially vulnerable operation that could lead to a denial of service
cursor = connection.cursor()
cursor.execute("SELECT * FROM your_table")
results = cursor.fetchall()
print(results)

connection.close()