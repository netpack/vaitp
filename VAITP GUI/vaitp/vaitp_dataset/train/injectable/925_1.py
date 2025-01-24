import psycopg2

# Function to safely execute a cypher query using parameterization
def execute_cypher_query(graph_name, cypher_query, params):
    # Establish connection to PostgreSQL
    conn = psycopg2.connect(database="your_database", user="your_user", password="your_password", host="localhost", port="5432")
    cursor = conn.cursor()
    
    # Use a safe method to insert the graph name and cypher query
    # This assumes a new function `set_cypher_params` has been created in the database
    
    try:
        cursor.callproc("set_cypher_params", (graph_name, cypher_query))
    
        # Now execute the cypher() function without risk of SQL injection
        cursor.execute("SELECT cypher()")
        
        # Fetch results
        results = cursor.fetchall()
    except psycopg2.Error as e:
        conn.rollback()
        raise e
    finally:
        # Clean up
        cursor.close()
        conn.commit()
        conn.close()
    
    return results

# Example usage
graph_name = "my_graph"
cypher_query = "MATCH (n) RETURN n"
params = {}  # Additional parameters can be passed here if needed
try:
    results = execute_cypher_query(graph_name, cypher_query, params)
    print(results)
except psycopg2.Error as e:
    print(f"An error occurred: {e}")
