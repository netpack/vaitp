def vulnerable_insert(query):
    # Directly passing the query to eval, which can lead to arbitrary code execution
    eval(query)

# Example of a vulnerable insert
vulnerable_insert("print('This is an arbitrary code execution!')")