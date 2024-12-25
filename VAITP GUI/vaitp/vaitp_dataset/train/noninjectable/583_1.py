import psycopg2

def unsafe_insert(connection, user_input):
    # Directly embedding user input into the SQL query, which can lead to SQL injection
    query = "INSERT INTO users (username) VALUES (%s)"
    with connection.cursor() as cursor:
        cursor.execute(query, (user_input,))

# Example usage
if __name__ == "__main__":
    conn = psycopg2.connect("dbname=test user=postgres password=secret")
    user_input = "user_input_with_multibyte_字符"  # Example multibyte input
    unsafe_insert(conn, user_input)
    conn.commit()
    conn.close()