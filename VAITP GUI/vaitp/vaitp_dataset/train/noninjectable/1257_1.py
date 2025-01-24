import mysql.connector

def connect_to_database(host, user, password, database):
    try:
        mydb = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        return mydb
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

def execute_query(mydb, query):
    if mydb is None:
        print("No database connection available.")
        return
    try:
      
        mycursor = mydb.cursor()
        mycursor.execute(query)
        mydb.commit()
        mycursor.close()
        print("Query executed successfully.")
    except mysql.connector.Error as err:
        print(f"Error executing query: {err}")
    
def vulnerable_code(host, user, password, database, input_query):
    mydb = connect_to_database(host,user,password,database)
    
    if mydb is not None:
        #VULNERABILITY - User supplied input_query is executed directly
        execute_query(mydb, input_query)
        mydb.close()



if __name__ == '__main__':
    
    host = "your_mysql_host"
    user = "your_mysql_user"
    password = "your_mysql_password"
    database = "your_mysql_database"

    #Simulating a user provided input
    malicious_input = "DROP TABLE users;" 
    print("Executing malicious query: " + malicious_input)
    vulnerable_code(host, user, password, database, malicious_input)

    #Simulating a different user provided input 
    benign_input = "SELECT * FROM products WHERE price > 100"
    print("Executing benign query: " + benign_input)
    vulnerable_code(host, user, password, database, benign_input)