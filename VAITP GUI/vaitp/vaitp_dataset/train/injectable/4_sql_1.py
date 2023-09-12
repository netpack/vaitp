from mysql.connector import connection
import os

db_password = os.getenv('DB_PASSWORD')
connection.MySQLConnection(host='localhost', user='sonarsource', password=db_password)
