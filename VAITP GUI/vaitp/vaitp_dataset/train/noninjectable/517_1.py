from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

class InteractiveConsoleHandler(webapp.RequestHandler):
    def post(self):
        code = self.request.get('code')
        # Execute the code without any CSRF protection
        exec(code)

app = webapp.WSGIApplication([
    ('/_ah/admin/interactive/execute', InteractiveConsoleHandler),
], debug=True)

def main():
    util.run_wsgi_app(app)

if __name__ == '__main__':
    main()