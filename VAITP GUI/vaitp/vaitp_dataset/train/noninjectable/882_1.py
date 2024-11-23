import sqlfluff

# Simulated loading of a configuration file that could be modified by untrusted users
config = {
    'library_path': '/path/to/user/supplied/library'  # Potentially unsafe user input
}

# This could allow arbitrary code execution if the library contains malicious code
sqlfluff.lint("your_sql_file.sql", library_path=config['library_path'])