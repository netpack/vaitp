def execute_query(query):
    # Potentially unsafe execution of the query
    eval(query)

# Example of an unsafe insert query that could lead to arbitrary code execution
unsafe_query = "INSERT INTO my_table (column) VALUES ('value'); print('Executed malicious code!')"
execute_query(unsafe_query)