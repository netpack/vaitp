import requests
import http.cookiejar

cj = http.cookiejar.CookieJar()
cj.set_cookie('name', 'value', domain='example.com')
response = requests.get('http://pythonicexample.com', cookies=cj)