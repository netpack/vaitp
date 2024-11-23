import psycopg2

# Vulnerable function that directly interpolates user input into the query
def execute_vulnerable_cypher_query(graph_name, cypher_query):
    # Establish connection to PostgreSQL
    conn = psycopg2.connect(database="your_database", user="your_user", password="your_password", host="localhost", port="5432")
    cursor = conn.cursor()
    
    # Directly embedding user input into the SQL command
    sql = f"SELECT cypher('{graph_name}', '{cypher_query}')"
    
    # Execute the potentially vulnerable query
    cursor.execute(sql)
    
    # Fetch results
    results = cursor.fetchall()
    
    # Clean up
    cursor.close()
    conn.commit()
    conn.close()
    
    return results

# Example usage with potential for SQL injection
graph_name = "my_graph"
cypher_query = "MATCH (n) RETURN n; DROP TABLE users;"  # Malicious input
results = execute_vulnerable_cypher_query(graph_name, cypher_query)
print(results)