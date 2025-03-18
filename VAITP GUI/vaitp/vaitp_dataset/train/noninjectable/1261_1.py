import snowflake.connector
import pandas as pd
from snowflake.connector.pandas_tools import write_pandas

def vulnerable_write_to_snowflake(conn, table_name, df):
    """
    This function is vulnerable to SQL injection.
    """
    escaped_table_name = table_name #Missing escaping or sanitization, vulnerable to SQL injection
    
    success, nchunks, nrows, _ = write_pandas(conn,
            df,
            escaped_table_name,
            auto_create_table=True,
            table_type=None,
            overwrite=False)


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
    data = {'col1': [1, 2, 3], 'col2': ['a', 'b', 'c']}
    df = pd.DataFrame(data)

    # Vulnerable table name
    vulnerable_table_name = "my_table; DROP TABLE my_table;"

    # Attempt to write data with the vulnerable table name
    try:
       vulnerable_write_to_snowflake(conn, vulnerable_table_name, df)
    except Exception as e:
        print(f"Error writing to Snowflake: {e}")
    
    conn.close()