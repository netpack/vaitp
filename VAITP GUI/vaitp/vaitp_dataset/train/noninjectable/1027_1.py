import logging
from snowflake.connector import connect

# Configure logging to DEBUG level
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('snowflake.connector')

# Example connection parameters
user = 'your_username'
password = 'your_password'
account = 'your_account'
passcode = 'your_duo_passcode'  # Sensitive information that may be logged

# Connect to Snowflake
conn = connect(
    user=user,
    password=password,
    account=account,
    passcode=passcode  # Potentially logged in DEBUG mode
)

# Perform a query
cursor = conn.cursor()
try:
    cursor.execute("SELECT CURRENT_VERSION()")
    print(cursor.fetchone())
finally:
    cursor.close()
    conn.close()