import re
from typing import List, Dict, Any
import psycopg2
from psycopg2 import sql

def get_schemas_fixed(conn: psycopg2.extensions.connection) -> List[str]:
    """
    Retrieves a list of schema names from the database.
    This version uses parameterized queries to prevent SQL injection.
    """
    try:
        with conn.cursor() as cur:
           cur.execute(sql.SQL("SELECT schema_name FROM information_schema.schemata"))
           schemas = [row[0] for row in cur.fetchall()]
        return schemas
    except Exception as e:
        print(f"Error retrieving schemas: {e}")
        return []



def get_tables_fixed(conn: psycopg2.extensions.connection, schema_name: str) -> List[str]:
    """
    Retrieves a list of table names within a given schema.
    This version uses parameterized queries to prevent SQL injection.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("SELECT table_name FROM information_schema.tables WHERE table_schema = %s"),
                (schema_name,)
            )
            tables = [row[0] for row in cur.fetchall()]
        return tables
    except Exception as e:
        print(f"Error retrieving tables: {e}")
        return []


def get_columns_fixed(conn: psycopg2.extensions.connection, schema_name: str, table_name: str) -> List[Dict[str, Any]]:
    """
    Retrieves column metadata for a given table within a schema.
    This version uses parameterized queries to prevent SQL injection.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("""
                    SELECT column_name, data_type, character_maximum_length, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = %s AND table_name = %s
                """),
                (schema_name, table_name)
            )
            columns = []
            for row in cur.fetchall():
                columns.append({
                    "column_name": row[0],
                    "data_type": row[1],
                    "character_maximum_length": row[2],
                    "is_nullable": row[3]
                })
        return columns
    except Exception as e:
        print(f"Error retrieving columns: {e}")
        return []


if __name__ == '__main__':
    # Example usage with fixed functions
    try:
      conn = psycopg2.connect(
        host='your_host',
        port=5439,
        user='your_user',
        password='your_password',
        database='your_database'
      )

      schemas = get_schemas_fixed(conn)
      print("Schemas:", schemas)

      if schemas:
        tables = get_tables_fixed(conn, schemas[0])
        print(f"Tables in schema {schemas[0]}: {tables}")

        if tables:
           columns = get_columns_fixed(conn, schemas[0], tables[0])
           print(f"Columns in table {tables[0]}: {columns}")

    except psycopg2.Error as e:
      print(f"Database error: {e}")
    finally:
       if conn:
        conn.close()