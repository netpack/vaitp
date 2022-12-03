file = "file_1.py"
def sanitize(file):
    html.escape(request.GET.get(file))

if __name__ == '__main__':
    sanitize(file)