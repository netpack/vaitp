import mysql.connector

def insecure_database_connection(host, user, password, database):
    try:
        # Establish a connection without SSL
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
            # SSL options are not specified, making the connection insecure
        )
        print("Connection established without SSL.")
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")

# Example usage
# connection = insecure_database_connection('localhost', 'user', 'password', 'database')