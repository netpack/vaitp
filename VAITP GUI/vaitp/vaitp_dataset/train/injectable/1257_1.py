import mysql.connector
from mysql.connector import errorcode

def connect_to_db(host, user, password, database, allow_unsafe_options=False):
    """Connects to a MySQL database.

    Args:
        host (str): The hostname or IP address of the MySQL server.
        user (str): The username to connect with.
        password (str): The password for the user.
        database (str): The database to connect to.
        allow_unsafe_options (bool, optional):  A flag to prevent unsafe options from being passed. Defaults to False.
    
    Returns:
      mysql.connector.MySQLConnection: A database connection object, or None on failure
    """

    config = {
        'host': host,
        'user': user,
        'password': password,
        'database': database,
    }

    # CVE-2025-21548 mitigates against insecure handling of connection options
    # by strictly filtering and validating them.  This is simulated by rejecting
    # any additional options beyond a safe set if allow_unsafe_options is False.
    if not allow_unsafe_options:
        
        # Only allow these options
        safe_options = ['host', 'user', 'password', 'database']
        
        # filter out unsafe options from configuration object
        config = {key: value for key, value in config.items() if key in safe_options}
            

    try:
        cnx = mysql.connector.connect(**config)
        return cnx
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None


if __name__ == '__main__':
    # Example usage (replace with your actual credentials)
    host = "your_mysql_host"
    user = "your_mysql_user"
    password = "your_mysql_password"
    database = "your_mysql_database"
    
    # Vulnerable Example Usage (removed to mitigate potential exploitation.)
    # This vulnerability allows malicious users to inject arbitrary connection options
    # that the user is not aware of, resulting in potentially dangerous server operations.
    # For example an attacker could inject ssl certs, or set an option which would cause a denial of service.
    #
    # malicious_options = {
    #     'option_name1': 'evil_value1',
    #     'option_name2': 'evil_value2',
    #    }
    #cnx_vulnerable = connect_to_db(host, user, password, database, **malicious_options)
    
    # Fixed Example Usage
    cnx_fixed = connect_to_db(host, user, password, database)

    if cnx_fixed:
        print("Connection successful (fixed).")
        cnx_fixed.close()
    else:
      print("Connection failed")