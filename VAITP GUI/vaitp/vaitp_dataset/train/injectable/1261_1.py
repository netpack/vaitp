import snowflake.connector
from snowflake.connector import DictCursor
from snowflake.connector.pandas_tools import write_pandas
import pandas as pd

def fixed_write_pandas(conn, df, table_name, database=None, schema=None):
    """
    This function demonstrates a safer approach to writing pandas DataFrames to Snowflake,
    mitigating the SQL injection vulnerability (CVE-2025-24793) present in older versions
    of the `snowflake.connector.pandas_tools.write_pandas` function.

    It leverages parameterized queries to prevent injection.

    Args:
      conn: A Snowflake connection object.
      df: A pandas DataFrame to write to Snowflake.
      table_name: The name of the table to write to.
      database: The database to use (optional).
      schema: The schema to use (optional).
    """

    if database:
        conn.cursor().execute(f"USE DATABASE {database}")
    if schema:
       conn.cursor().execute(f"USE SCHEMA {schema}")

    columns = df.columns
    placeholders = ", ".join(["%s"] * len(columns))
    column_names = ", ".join([f'"{col}"' for col in columns]) # Quote identifiers to avoid SQL injection.

    sql = f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders})"

    
    # Use executemany for batch insertion, which is more efficient than looping.
    # Convert dataframe rows to a list of tuples.
    
    data = [tuple(row) for row in df.values.tolist()]
    with conn.cursor() as cursor:
        cursor.executemany(sql, data)
    
if __name__ == '__main__':
    # Example usage (replace with your actual Snowflake connection details)
    conn = snowflake.connector.connect(
        user='your_user',
        password='your_password',
        account='your_account',
        warehouse='your_warehouse',
        database='your_database',
        schema='your_schema'
    )


    # Create a sample DataFrame
    data = {'name': ['Alice', 'Bob', 'Charlie'],
            'age': [25, 30, 28],
             'city': ["New York", "London", "Paris"]
           }
    df = pd.DataFrame(data)

    # Specify table name
    table_name = 'my_table'
    
    # Create table if it doesn't exist (you may want to handle this differently)
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE OR REPLACE TABLE {table_name} (name STRING, age INT, city STRING)")
    except Exception as e:
            print (f"Error creating table: {e}")

    # Use the safer write function
    try:
        fixed_write_pandas(conn, df, table_name)
        print("Data written to Snowflake successfully!")
    except Exception as e:
        print(f"Error writing to Snowflake: {e}")
    
    conn.close()