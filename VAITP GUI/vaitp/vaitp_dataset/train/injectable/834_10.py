import html
from urllib.parse import quote

description = "access your data"
redirect_url = "https://example.com/login"

html_content = f"""
<html>
<head>
    <title>Authentication</title>
</head>
    <body>
        <div>
            <p>
                A client is trying to {html.escape(description)}. To confirm this action,
                <a href="{html.escape(quote(redirect_url, safe='/:'))}">re-authenticate with single sign-on</a>.
                If you did not expect this, your account may be compromised!
            </p>
        </div>
    </body>
</html>
"""
