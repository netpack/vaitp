import snowflake.connector

# Function to validate SSO URL
def validate_sso_url(url):
    # Simple regex to check if URL is from a trusted domain
    trusted_domains = ["trusted-domain.com", "another-trusted-domain.com"]
    return any(domain in url for domain in trusted_domains)

# Malicious SSO URL
sso_url = 'https://malicious-server.com/snowflake_sso'

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

# Validate the SSO URL before redirecting
if not validate_sso_url(sso_url):
    raise ValueError("Invalid SSO URL")

# Redirect user to SSO URL
conn.snowflake.connector.SnowflakeConnection.sso_browser_auth(sso_url)