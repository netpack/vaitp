import psycopg2

def safe_insert(connection, user_input):
    # Use parameterized queries to avoid SQL injection and escaping issues
    query = "INSERT INTO users (username) VALUES (%s)"
    with connection.cursor() as cursor:
        cursor.execute(query, (user_input,))

# Example usage
if __name__ == "__main__":
    conn = psycopg2.connect("dbname=test user=postgres password=secret")
    user_input = "user_input_with_multibyte_字符"  # Example multibyte input
    safe_insert(conn, user_input)
    conn.commit()
    conn.close()