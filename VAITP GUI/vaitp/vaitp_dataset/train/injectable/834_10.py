# This is not valid Python code. It's HTML.
# If you wanted to use Python to generate this HTML, you could use string formatting or templating.

# Example using string formatting:

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
                A client is trying to {description}. To confirm this action,
                <a href="{redirect_url}">re-authenticate with single sign-on</a>.
                If you did not expect this, your account may be compromised!
            </p>
        </div>
    </body>
</html>
"""

# print(html_content) # This would output the HTML string, not execute it as Python