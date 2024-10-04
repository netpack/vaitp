import http.cookiejar

# Create a cookie jar object
cj = http.cookiejar.CookieJar()

# Set some cookies for example.com
cj.set_cookie("name", "value", domain="example.com")

# Create a default policy object with pythonicexample.com as the domain
dp = http.cookiejar.DefaultPolicy(domain="pythonicexample.com")

# Set the default policy for the cookie jar object
cj.set_policy(dp)

# Try to connect to an attacker-controlled server with pythonicexample.com as the domain
cj.load("http://attacker.pythonicexample.com")