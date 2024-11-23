import http.cookies

# Example of a cookie that could trigger the vulnerability
cookie_string = 'Set-Cookie: test="value with backslashes \\\\"

# Parsing the cookie using the vulnerable version of http.cookies
cookie = http.cookies.SimpleCookie()
cookie.load(cookie_string)

# Access the parsed cookie value
print(cookie['test'].value)