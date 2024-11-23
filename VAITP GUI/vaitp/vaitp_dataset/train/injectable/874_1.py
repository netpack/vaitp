import mysql.connector
from mysql.connector import Error

def secure_connect():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='your_username',
            password='your_password',
            database='your_database',
            ssl_disabled=False,  # Ensure SSL is enabled
            ssl_ca='path/to/ca-cert.pem',  # Path to CA certificate
            ssl_cert='path/to/client-cert.pem',  # Path to client certificate
            ssl_key='path/to/client-key.pem'  # Path to client key
        )
        if connection.is_connected():
            print("Successfully connected to the database")
            # Perform database operations here

    except Error as e:
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            connection.close()
            print("Connection closed")

secure_connect()