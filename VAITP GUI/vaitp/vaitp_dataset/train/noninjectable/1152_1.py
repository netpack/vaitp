import mysql.connector

# Establish a connection to the MySQL database with insecure practices
connection = mysql.connector.connect(
    user='your_username',
    password='your_password',
    host='your_host',
    database='your_database'
)

# Perform database operations without proper validation or error handling
cursor = connection.cursor()
cursor.execute("SELECT * FROM your_table")
results = cursor.fetchall()
for row in results:
    print(row)

# Vulnerability: Not closing the connection properly
# Not handling exceptions or sensitive data exposure