import sqlparse

# Example of how to use sqlparse without the vulnerability
# This code avoids using the strip_comments=True option
sql = """
-- This is a comment
SELECT * FROM users;  -- Another comment
"""

# Proper usage without triggering the vulnerability
formatted_sql = sqlparse.format(sql, strip_comments=False)
print(formatted_sql)