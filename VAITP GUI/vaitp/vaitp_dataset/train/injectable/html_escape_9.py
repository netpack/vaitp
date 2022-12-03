import sys
def sanitize(file):
    html.escape(request.GET.get(file))

if __name__ == '__main__':
    sanitize(sys.argv[1])