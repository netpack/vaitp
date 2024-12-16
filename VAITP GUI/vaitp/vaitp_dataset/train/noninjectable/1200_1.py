import tornado.web
import tornado.ioloop

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        # Simulating a vulnerable cookie parsing scenario
        cookie_header = "malicious_cookie=" + "a" * 1000000  # Large, crafted cookie
        self.request.headers['Cookie'] = cookie_header
        # This could lead to excessive CPU consumption
        parsed_cookies = self.get_cookies(self.request.headers['Cookie'])
        self.write("Parsed cookies: {}".format(parsed_cookies))

    def get_cookies(self, cookie_header):
        # Simulating a vulnerable cookie parsing function
        cookies = {}
        for cookie in cookie_header.split(';'):
            key, value = cookie.split('=', 1)
            cookies[key.strip()] = value.strip()
        return cookies

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()