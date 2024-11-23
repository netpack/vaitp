def vulnerable_update_query(query):
    # Directly passing user input to eval function
    eval(query)

# Example of a malicious update query
vulnerable_update_query("UPDATE my_table SET column='value'; os.system('malicious_command')")