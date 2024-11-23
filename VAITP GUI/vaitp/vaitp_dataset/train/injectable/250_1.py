import mysql.connector
from mysql.connector import errorcode

def secure_database_connection(host, user, password, database):
    try:
        # Establish a secure connection using SSL
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            ssl_disabled=False,  # Ensure SSL is enabled
            ssl_ca='path/to/ca-cert.pem',  # Path to CA certificate
            ssl_cert='path/to/client-cert.pem',  # Path to client certificate
            ssl_key='path/to/client-key.pem'  # Path to client key
        )
        print("Connection established securely.")
        return connection
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
# connection = secure_database_connection('localhost', 'user', 'password', 'database')