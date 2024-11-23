def execute_query(query):
    # Directly executing the query, which may contain arbitrary code
    eval(query)

# Example of an unsafe insert that could exploit the vulnerability
malicious_query = "INSERT INTO site_columns (name) VALUES ('malicious_code'); exec('os.system(\"ls\")')"
execute_query(malicious_query)