import mysql.connector

def vulnerable_connect():
    try:
        # Connecting without SSL, which is vulnerable to MITM attacks
        connection = mysql.connector.connect(
            host='localhost',
            user='your_username',
            password='your_password',
            database='your_database'
            # SSL parameters are omitted, making the connection insecure
        )
        if connection.is_connected():
            print("Successfully connected to the database")
            # Perform database operations here

    except mysql.connector.Error as e:
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            connection.close()
            print("Connection closed")

vulnerable_connect()