import html
import urllib.parse
import re

def request(url, method='GET', data=None, headers=None, cookies=None, insecure=False, param=None):
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    if not isinstance(method, str):
        raise ValueError("Method must be a string")
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("Headers must be a dictionary")
    if cookies is not None and not isinstance(cookies, dict):
      raise ValueError("Cookies must be a dictionary")
    if param is not None and not isinstance(param, dict):
        raise ValueError("Param must be a dictionary")

    parsed_url = urllib.parse.urlparse(url)

    if method.upper() == "GET" and data:
         
        if isinstance(data, dict):
             query_string = urllib.parse.urlencode(data, safe=":/")

        elif isinstance(data, str):
            query_string = data
        else:
            query_string = str(data)

        if parsed_url.query:
           url = f"{url}&{query_string}"
        else:
            url = f"{url}?{query_string}"
    
    
    elif method.upper() != 'GET' and isinstance(data, dict) and headers and headers.get('Content-Type') == "application/x-www-form-urlencoded":
        data = urllib.parse.urlencode(data)
    
    
    return url, method, data, headers, cookies, insecure, param

class RESTBuilderInstance:
     def __init__(self, url):
          self.url = url
          self.method = "GET"
          self.data = None
          self.headers = {}
          self.cookies = {}
          self.insecure = False
          self.param = None
          self.keepalive_flag = False


     def method(self, method, data=None):
         self.method = method
         if data is not None:
              self.data = data
         return self
     
     def data(self, data):
        self.data = data
        return self

     def header(self, key, value):
         self.headers[key] = value
         return self

     def headers(self, headers):
         self.headers.update(headers)
         return self

     def cookie(self, key, value):
        self.cookies[key] = value
        return self
     
     def cookies(self, cookies):
        self.cookies.update(cookies)
        return self
     
     def insecure(self):
         self.insecure = True
         return self
     
     def param(self, param):
        self.param = param
        return self

     def keepalive(self):
        self.keepalive_flag = True
        return self

     def url(self, url=None):
          if url:
              return RESTBuilderInstance(url)
          return self.url

     def get(self, data=None):
        return self.method("GET", data)
     
     def post(self, data=None):
        return self.method("POST", data)
     
     def put(self, data=None):
          return self.method("PUT", data)
     
     def patch(self, data=None):
          return self.method("PATCH", data)
     
     def delete(self, data=None):
        return self.method("DELETE", data)
     
     def callback(self, callback):
         url, method, data, headers, cookies, insecure, param = request(self.url, self.method, self.data, self.headers, self.cookies, self.insecure, self.param)
         return callback(url, method, data, headers, cookies, insecure, param)
     
     def exec(self):
        url, method, data, headers, cookies, insecure, param = request(self.url, self.method, self.data, self.headers, self.cookies, self.insecure, self.param)
        return url, method, data, headers, cookies, insecure, param


class RESTBuilder:
     def __init__(self):
          pass

     def url(self, url):
         return RESTBuilderInstance(url)

     def insecure(self):
         return RESTBuilderInstance().insecure()


def sitemap_url2(url, args):
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    if not isinstance(args, (tuple,list)):
        raise ValueError("Args must be a tuple or list")
   
    safe_args = []
    for arg in args:
         safe_args.append(html.escape(str(arg)))
    
    query_string = urllib.parse.urlencode(safe_args)
    
    if query_string:
        return f"{url}?{query_string}"
    return url