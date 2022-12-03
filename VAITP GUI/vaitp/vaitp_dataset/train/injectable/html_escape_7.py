file = "file_1.py"
def sanitize(file):
    html.escape(request.GET.get(file))

sanitize(file)